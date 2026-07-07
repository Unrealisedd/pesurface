# pesurface — Development Notes

## What this is
A Windows PE attack surface mapper for LPE/privilege escalation hunting.
Takes a PE binary (service, driver, COM server, DLL) and extracts everything
relevant to local privilege escalation — dangerous API patterns, named pipes,
RPC interfaces, IOCTL handlers, DLL hijack candidates, impersonation calls.

Outputs a structured report (terminal + JSON). Optionally integrates with
Ghidra headless for deeper analysis (decompilation, argument tracing, call graphs).

## Architecture
- Python CLI tool
- `pefile` for PE parsing (imports, exports, sections, resources)
- `capstone` for lightweight disassembly (tracing API call arguments)
- Ghidra headless integration via Java GhidraScript for deep analysis
- String extraction for pipe names, registry paths, COM CLSIDs
- Modular analyzers — each detector is a separate module

## Modules (build order)

### v0.1 — Core + Import Analysis
- [x] Project scaffolding (CLI, config, output)
- [x] PE loader (pefile wrapper)
- [x] Import analyzer — flag dangerous APIs by category (120+ APIs across 15 categories)
- [x] String extraction — named pipes, registry paths, UNC paths, file paths, GUIDs/CLSIDs, SDDL, commands
- [x] DLL hijack candidate detection — KnownDlls filtering, search order hijack
- [x] Report output (color terminal + JSON)

### v0.2 — Deeper Analysis
- [x] IOCTL dispatch table extraction for .sys drivers
- [x] Cross-reference imports with strings (which API uses which path)
- [x] Security descriptor / DACL pattern detection (SDDL parsing + weak permission flagging)
- [x] Export analysis for COM/RPC server DLLs (ServiceMain, SvchostPushServiceGlobals, DllGetClassObject)
- [x] PE metadata (signing, ASLR, DEP, CFG, integrity level)

### v0.3 — Ghidra Integration
- [x] Ghidra headless decompilation backend (Java GhidraScript + Python runner)
- [x] Trace API call arguments to string literals (LoadLibrary paths, pipe names, SDDL strings)
- [x] Call graph from entry points (ServiceMain, DriverEntry, DllMain, main, etc.)
- [x] Decompiled code pattern matching (NULL DACL, missing RevertToSelf, METHOD_NEITHER, format string injection)
- [x] --ghidra-json for loading cached results without re-running Ghidra

## Usage
```
python -m pesurface <binary.exe|dll|sys>
python -m pesurface <binary> --json output.json
python -m pesurface <binary> -q
python -m pesurface <binary> --no-color > report.txt

# With Ghidra deep analysis
python -m pesurface <binary> --ghidra
python -m pesurface <binary> --ghidra --ghidra-path /path/to/analyzeHeadless
python -m pesurface <binary> --ghidra-json cached_results.json
```

## Test Results

### v0.1 — spoolsv.exe (Print Spooler SYSTEM service)
- 27 dangerous imports (12 critical/high)
- 6 DLL hijack candidates
- 31 interesting strings (SDDL, privileges, registry paths)
- 64 total findings

### v0.2 — spoolsv.exe + StorSvc.dll
- spoolsv.exe: 81 total findings (27 imports, 6 hijack, 31 strings, 2 SDDL, 15 exports)
- StorSvc.dll: 93 total findings (36 imports, 5 hijack, 47 strings, 5 exports)
  - Correctly identified as svchost-hosted service DLL
  - SDDL parser flagged untrusted integrity mandatory labels

### v0.3 — Ghidra integration
- notepad.exe: 32 traced API calls, 1 call graph (entry->CreateFileW), 19 decompiled functions
  - Resolved args: `probe.autosave` for CreateFileW, source path for ShellExecuteW
- spoolsv.exe: 148 traced calls, 108 decompiled functions, 3 insights
  - Confirmed LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800) used in all LoadLibrary calls
  - SetThreadToken traced to ProcessUserLogon with WTSQueryUserToken/DuplicateTokenEx context
  - 260 total findings with Ghidra enabled
