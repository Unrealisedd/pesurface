"""DLL hijack candidate detection.

Checks imported DLLs against the KnownDlls list and system32 contents
to find DLLs that might be hijackable via search order abuse.
"""

from dataclasses import dataclass
from typing import List, Set
from ..loader import PEInfo


# KnownDlls — loaded from System32 regardless of search order.
# From HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
# Plus common system DLLs that are always in System32.
KNOWN_DLLS: Set[str] = {
    # Actual KnownDlls registry entries (Windows 10/11)
    "_wow64cpu.dll", "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll",
    "cfgmgr32.dll", "clbcatq.dll", "combase.dll", "comctl32.dll",
    "comdlg32.dll", "coml2.dll", "crypt32.dll", "cryptsp.dll",
    "dbghelp.dll", "difxapi.dll", "gdi32.dll", "gdi32full.dll",
    "gdiplus.dll", "gl.dll", "iertutil.dll", "imagehlp.dll",
    "imm32.dll", "kernel32.dll", "kernelbase.dll", "msvcp_win.dll",
    "msvcrt.dll", "nsi.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll",
    "powrprof.dll", "profapi.dll", "psapi.dll", "rpcrt4.dll",
    "sechost.dll", "setupapi.dll", "shell32.dll", "shcore.dll",
    "shlwapi.dll", "ucrtbase.dll", "user32.dll", "uxtheme.dll",
    "win32u.dll", "windows.storage.dll", "wldp.dll", "wow64.dll",
    "wow64base.dll", "wow64con.dll", "wow64cpu.dll", "wow64win.dll",
    "ws2_32.dll",
    # Common system DLLs that effectively always resolve from system32
    "mswsock.dll", "msctf.dll", "version.dll", "winmm.dll",
    "winspool.drv", "wintrust.dll", "winhttp.dll", "wininet.dll",
    "urlmon.dll", "cryptbase.dll", "sspicli.dll", "msasn1.dll",
    "cabinet.dll", "msi.dll", "netapi32.dll", "samcli.dll",
    "iphlpapi.dll", "dnsapi.dll", "userenv.dll", "wtsapi32.dll",
    "authz.dll", "ncrypt.dll",
    # CRT DLLs
    "vcruntime140.dll", "vcruntime140_1.dll", "vcruntime140d.dll",
    "msvcp140.dll", "msvcp140_1.dll", "msvcp140d.dll",
    "ucrtbased.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
    # NTDLL/kernel
    "ntoskrnl.exe", "hal.dll", "ci.dll",
}

# API set DLLs — virtual DLLs that redirect to real system DLLs
API_SET_PREFIX = "api-ms-win-"
EXT_API_SET_PREFIX = "ext-ms-win-"


@dataclass
class HijackCandidate:
    dll_name: str
    reason: str
    imported_functions: List[str]
    is_delay_loaded: bool


def analyze(pe_info: PEInfo) -> List[HijackCandidate]:
    candidates = []

    for dll_name, functions in pe_info.imports.items():
        is_delay = dll_name.endswith(" (delay)")
        clean_name = dll_name.replace(" (delay)", "").strip()
        lower = clean_name.lower()

        # Skip API set DLLs
        if lower.startswith(API_SET_PREFIX) or lower.startswith(EXT_API_SET_PREFIX):
            continue

        # Skip known system DLLs
        if lower in KNOWN_DLLS:
            continue

        # Skip obvious system DLLs by path pattern
        if lower.startswith("c:\\windows"):
            continue

        reason = _classify(clean_name, is_delay)
        if reason:
            candidates.append(HijackCandidate(
                dll_name=clean_name,
                reason=reason,
                imported_functions=functions,
                is_delay_loaded=is_delay,
            ))

    return candidates


def _classify(dll_name: str, is_delay: bool) -> str:
    lower = dll_name.lower()

    # DLLs without a path are resolved via search order
    if "\\" not in lower and "/" not in lower:
        if is_delay:
            return "Delay-loaded DLL resolved via search order — plant in application directory"
        return "DLL resolved via search order — plant in application directory or CWD"

    return ""
