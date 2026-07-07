"""Ghidra-based deep analysis — processes results from headless decompilation.

Consumes GhidraResults and produces:
- Traced API call arguments (which string gets passed to LoadLibrary, etc.)
- Call graph paths from entry points to dangerous APIs
- Function-level risk assessment based on decompiled code patterns
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from ..ghidra.runner import GhidraResults, ApiCallTrace, CallGraphEntry


@dataclass
class TracedCall:
    api: str
    caller: str
    address: str
    resolved_args: List[str]
    risk_note: str


@dataclass
class EntryToApiPath:
    entry_point: str
    api: str
    path: List[str]


@dataclass
class DecompiledInsight:
    function: str
    address: str
    pattern: str
    detail: str
    severity: str


@dataclass
class GhidraFindings:
    traced_calls: List[TracedCall] = field(default_factory=list)
    entry_paths: List[EntryToApiPath] = field(default_factory=list)
    insights: List[DecompiledInsight] = field(default_factory=list)


LOADLIB_APIS = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"}
PIPE_APIS = {"CreateNamedPipeA", "CreateNamedPipeW"}
PROCESS_APIS = {"CreateProcessA", "CreateProcessW", "CreateProcessAsUserA",
                "CreateProcessAsUserW", "WinExec", "system", "_wsystem",
                "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW"}
IMPERSONATION_APIS = {"ImpersonateNamedPipeClient", "RpcImpersonateClient",
                      "CoImpersonateClient", "ImpersonateLoggedOnUser"}
FILE_APIS = {"CreateFileA", "CreateFileW", "MoveFileA", "MoveFileW",
             "MoveFileExA", "MoveFileExW", "DeleteFileA", "DeleteFileW",
             "CopyFileA", "CopyFileW", "ReplaceFileA", "ReplaceFileW",
             "CreateHardLinkA", "CreateHardLinkW", "CreateSymbolicLinkA", "CreateSymbolicLinkW"}
SDDL_APIS = {"ConvertStringSecurityDescriptorToSecurityDescriptorA",
             "ConvertStringSecurityDescriptorToSecurityDescriptorW"}

DANGEROUS_DECOMPILE_PATTERNS = [
    (r'LoadLibrary[AW]\s*\(\s*["\']([^"\']+)', "dll_load_string",
     "LoadLibrary called with string literal", "high"),
    (r'LoadLibrary[AW]\s*\(\s*\w+\s*\)', "dll_load_variable",
     "LoadLibrary called with variable — check if attacker-controlled", "medium"),
    (r'LOAD_LIBRARY_SEARCH_SYSTEM32|0x800\b', "safe_loadlib",
     "Uses LOAD_LIBRARY_SEARCH_SYSTEM32 flag — safe LoadLibrary pattern", "info"),
    (r'NULL\s*,\s*NULL\s*\)\s*;\s*$', "null_dacl_pattern",
     "Potential NULL DACL — check SetSecurityDescriptorDacl args", "high"),
    (r'ImpersonateNamedPipeClient.*?(?!RevertToSelf)', "missing_revert",
     "Impersonation without nearby RevertToSelf", "high"),
    (r'CreateNamedPipe[AW]\s*\([^)]*PIPE_ACCESS_DUPLEX', "duplex_pipe",
     "Duplex named pipe — can be used for impersonation", "medium"),
    (r'SetSecurityDescriptorDacl\s*\([^,]+,\s*TRUE\s*,\s*NULL', "null_dacl_explicit",
     "Explicit NULL DACL — object accessible by Everyone", "critical"),
    (r'DeviceIoControl\s*\([^)]+METHOD_NEITHER', "method_neither",
     "IOCTL with METHOD_NEITHER — raw user pointers", "high"),
    (r'MmMapLockedPagesSpecifyCache\s*\([^)]*UserMode', "user_mapping",
     "Kernel maps pages to user mode — potential arbitrary R/W", "critical"),
    (r'%s.*CreateProcess|CreateProcess.*%s', "format_string_cmd",
     "Format string in process creation — possible command injection", "high"),
    (r'sprintf|swprintf|_snprintf.*\bpath\b', "sprintf_path",
     "String formatting with path variable — check for path injection", "medium"),
]


def analyze(ghidra_results: GhidraResults) -> GhidraFindings:
    findings = GhidraFindings()

    _analyze_traced_calls(ghidra_results, findings)
    _analyze_call_graphs(ghidra_results, findings)
    _analyze_decompiled(ghidra_results, findings)

    return findings


def _analyze_traced_calls(gr: GhidraResults, findings: GhidraFindings):
    for ac in gr.api_calls:
        risk = _assess_call_risk(ac)
        findings.traced_calls.append(TracedCall(
            api=ac.api,
            caller=ac.caller,
            address=ac.address,
            resolved_args=ac.resolved_args,
            risk_note=risk,
        ))


def _assess_call_risk(ac: ApiCallTrace) -> str:
    api = ac.api
    args = ac.resolved_args

    if api in LOADLIB_APIS:
        if args:
            dll = args[0] if args else ""
            if "\\" not in dll and "/" not in dll:
                return f"LoadLibrary({dll}) — no full path, hijackable via search order"
            if "system32" in dll.lower() or "syswow64" in dll.lower():
                return f"LoadLibrary({dll}) — system path, likely safe"
            return f"LoadLibrary({dll}) — check if path is writable"
        return "LoadLibrary with unresolved argument — needs manual review"

    if api in PIPE_APIS:
        if args:
            pipe = next((a for a in args if "pipe" in a.lower()), args[0] if args else "")
            return f"Named pipe: {pipe} — check DACL and impersonation"
        return "CreateNamedPipe with unresolved name"

    if api in PROCESS_APIS:
        if args:
            return f"Process creation with arg: {args[0][:80]} — check for injection"
        return "Process creation — resolve command line argument"

    if api in SDDL_APIS:
        if args:
            sddl = next((a for a in args if "D:" in a or "O:" in a), "")
            if sddl:
                return f"SDDL: {sddl[:60]} — parse for weak permissions"
        return "SDDL conversion — extract the descriptor string"

    if api in IMPERSONATION_APIS:
        return "Impersonation call — verify RevertToSelf is called after"

    if api in FILE_APIS:
        if args:
            return f"File operation on: {args[0][:80]} — check for symlink/junction"
        return "File operation — resolve path argument"

    return ""


def _analyze_call_graphs(gr: GhidraResults, findings: GhidraFindings):
    dangerous_set = (LOADLIB_APIS | PIPE_APIS | PROCESS_APIS |
                     IMPERSONATION_APIS | FILE_APIS | SDDL_APIS)

    for cg in gr.call_graphs:
        paths = []
        _find_dangerous_paths(cg.tree, [cg.entry], dangerous_set, paths)
        for api, path in paths:
            findings.entry_paths.append(EntryToApiPath(
                entry_point=cg.entry,
                api=api,
                path=path,
            ))


def _find_dangerous_paths(tree, current_path, dangerous_set, results):
    for node in tree:
        name = node.get("name", "")
        new_path = current_path + [name]

        if name in dangerous_set:
            results.append((name, new_path))

        children = node.get("calls", [])
        if children:
            _find_dangerous_paths(children, new_path, dangerous_set, results)


def _analyze_decompiled(gr: GhidraResults, findings: GhidraFindings):
    for fn in gr.functions:
        if not fn.decompiled:
            continue

        for pattern, pattern_id, desc, severity in DANGEROUS_DECOMPILE_PATTERNS:
            matches = re.findall(pattern, fn.decompiled, re.IGNORECASE | re.MULTILINE)
            if matches:
                detail = desc
                if isinstance(matches[0], str) and matches[0]:
                    detail = f"{desc}: {matches[0][:80]}"

                findings.insights.append(DecompiledInsight(
                    function=fn.name,
                    address=fn.address,
                    pattern=pattern_id,
                    detail=detail,
                    severity=severity,
                ))
