# pesurface

**PE Attack Surface Mapper** — static analysis tool that extracts local privilege escalation (LPE) attack surface from Windows PE binaries.

Feed it a service executable, kernel driver, COM server, or DLL and get a structured report of everything relevant to privilege escalation:

- **Dangerous API imports** — 120+ APIs across 15 categories (DLL loading, impersonation, token manipulation, named pipes, process creation, service control, COM, file ops, registry, credentials, drivers, security descriptors) flagged by severity with LPE relevance notes
- **DLL hijack candidates** — non-KnownDlls imports resolved via search order, including delay-loaded DLLs
- **Interesting strings** — named pipes, registry paths, CLSIDs, SDDL descriptors, privilege names, UNC paths, embedded commands
- **Import-string cross-references** — maps dangerous API imports to their likely string arguments found in the same binary
- **SDDL analysis** — parses security descriptors and flags weak permissions (Everyone/Anonymous access, low integrity, NULL DACLs)
- **IOCTL extraction** — scans driver `.text` sections for IOCTL code comparisons, decodes device type/function/method/access, flags METHOD_NEITHER
- **Export analysis** — identifies COM servers (DllGetClassObject), service DLLs (ServiceMain/SvchostPushServiceGlobals), and driver entry points
- **PE hardening** — ASLR, DEP, CFG, Authenticode, ForceIntegrity, SEH protection
- **Ghidra integration** — optional deep analysis via Ghidra headless: traces API call arguments to string literals, builds call graphs from entry points, pattern-matches decompiled code for dangerous constructs

## Install

```
pip install -e .
```

Ghidra integration requires [Ghidra](https://ghidra-sre.org/) installed. Set `GHIDRA_HOME` or use `--ghidra-path`.

## Usage

```bash
# Full color report
pesurface C:\Windows\System32\spoolsv.exe

# JSON output for scripting
pesurface target.dll --json report.json

# Quiet mode (one-liner summary)
pesurface target.sys -q

# No color (piping to file)
pesurface target.exe --no-color > report.txt

# With Ghidra deep analysis (traces API arguments, builds call graphs, decompiles)
pesurface target.exe --ghidra

# Load cached Ghidra results (skip re-analysis)
pesurface target.exe --ghidra-json previous_results.json
```

## Example Output

```
                          ___
  _ __  ___  ___ _   _ _ / __| __ _  ___ ___
 | '_ \/ _ \/ __| | | | |__ \/ _` |/ __/ _ \
 | |_) |  __/\__ \ |_| | ___) | (_| | (_|  __/
 | .__/ \___||___/\__,_||____/ \__,_|\___\___|
 |_|      PE Attack Surface Mapper

TARGET
  Path:       C:\Windows\System32\spoolsv.exe
  Type:       Executable (x86_64)
  ...

HARDENING
  ASLR:             ON
  DEP/NX:           ON
  CFG:              ON
  ...

DANGEROUS IMPORTS (27)

  DLL LOADING
  !   LoadLibraryW [kernel32.dll]
      Loads DLL by name — search order hijackable without LOAD_LIBRARY_SEARCH_SYSTEM32

  IMPERSONATION
  !!  RpcImpersonateClient [RPCRT4.dll]
      If RPC endpoint is reachable by standard user, SYSTEM impersonation

GHIDRA: TRACED API CALLS (148)
  SetThreadToken in ProcessUserLogon @ 0x140015840
    Args: ProcessUserLogon, WTSQueryUserToken failed!  Error hr: %d.
    > ...

GHIDRA: DECOMPILED INSIGHTS (3)
  INFO FUN_14004d418 @ 0x14004d418
    Uses LOAD_LIBRARY_SEARCH_SYSTEM32 flag — safe LoadLibrary pattern

SUMMARY
  Total findings:   260
  Critical/High:    12
  Hijack candidates:6
  Ghidra findings:  151 (148 traced, 0 paths, 3 insights)
```

## Architecture

```
pesurface/
├── __main__.py          # CLI entry point
├── loader.py            # PE parser (pefile wrapper)
├── apidb.py             # 120+ dangerous API database with severity/LPE context
├── report.py            # Terminal + JSON output
├── analyzers/
│   ├── imports.py       # Cross-reference imports against apidb
│   ├── strings.py       # Pattern-match strings for pipes, registry, CLSIDs, etc.
│   ├── dllhijack.py     # KnownDlls filtering, search-order hijack detection
│   ├── metadata.py      # ASLR, DEP, CFG, signing, integrity checks
│   ├── ioctl.py         # IOCTL code extraction from driver .text sections
│   ├── sddl.py          # SDDL parsing and weak permission detection
│   ├── exports.py       # COM/service/driver binary type identification
│   ├── xref.py          # Import-string cross-referencing
│   └── ghidra_analysis.py  # Processes Ghidra output into findings
└── ghidra/
    ├── PesurfaceAnalyze.java  # GhidraScript for headless analysis
    └── runner.py              # Python wrapper for analyzeHeadless
```

## License

MIT
