"""Export analysis for COM servers, RPC servers, and service DLLs.

Identifies what kind of server a DLL is by its exports and flags
relevant attack surface.
"""

from dataclasses import dataclass
from typing import List
from ..loader import PEInfo


COM_EXPORTS = {
    "DllGetClassObject": "COM in-process server — serves COM objects to callers",
    "DllRegisterServer": "COM self-registration — writes CLSIDs to registry",
    "DllUnregisterServer": "COM unregistration",
    "DllCanUnloadNow": "COM lifetime management",
    "DllInstall": "COM installation entry point",
}

SERVICE_EXPORTS = {
    "ServiceMain": "Service entry point — runs as service account (often SYSTEM)",
    "SvchostPushServiceGlobals": "Svchost-hosted service (shared process, runs as SYSTEM)",
}

DRIVER_EXPORTS = {
    "DriverEntry": "Kernel driver entry point",
    "GsDriverEntry": "Kernel driver entry (/GS security cookie init)",
}

RPC_EXPORTS = {
    "Opnum0NotUsedOnWire": "RPC interface stub — auto-generated from IDL",
}

RUNDLL_EXPORTS = {
    "DllMain": "DLL entry point",
}

INTERESTING_PATTERNS = {
    "Install": "Installation/configuration entry point",
    "Uninstall": "Uninstallation entry point",
    "Configure": "Configuration entry point",
    "Register": "Registration entry point",
    "Init": "Initialization — may set up security state",
    "Callback": "Callback handler — check what triggers it",
}


@dataclass
class ExportFinding:
    name: str
    category: str
    description: str
    lpe_note: str


def analyze(pe_info: PEInfo) -> List[ExportFinding]:
    if not pe_info.exports:
        return []

    findings = []
    export_set = {e.lower(): e for e in pe_info.exports}

    is_com_server = "dllgetclassobject" in export_set
    is_service_dll = "servicemain" in export_set or "svchostpushserviceglobals" in export_set
    is_driver = "driverentry" in export_set or "gsdriverentry" in export_set

    for export in pe_info.exports:
        lower = export.lower()

        if lower in {k.lower(): k for k, v in COM_EXPORTS.items()}:
            key = next(k for k in COM_EXPORTS if k.lower() == lower)
            findings.append(ExportFinding(
                name=export, category="COM Server",
                description=COM_EXPORTS[key],
                lpe_note="COM server running as SYSTEM = cross-privilege activation attack surface"
                if is_com_server else "",
            ))
            continue

        if lower in {k.lower(): k for k, v in SERVICE_EXPORTS.items()}:
            key = next(k for k in SERVICE_EXPORTS if k.lower() == lower)
            findings.append(ExportFinding(
                name=export, category="Service",
                description=SERVICE_EXPORTS[key],
                lpe_note="Service DLL in svchost = SYSTEM-level code; look for RPC/pipe/COM endpoints",
            ))
            continue

        if lower in {k.lower(): k for k, v in DRIVER_EXPORTS.items()}:
            key = next(k for k in DRIVER_EXPORTS if k.lower() == lower)
            findings.append(ExportFinding(
                name=export, category="Driver",
                description=DRIVER_EXPORTS[key],
                lpe_note="Kernel driver = ring-0 code; focus on IOCTL handlers and input validation",
            ))
            continue

        for pattern, desc in INTERESTING_PATTERNS.items():
            if pattern.lower() in lower and export not in ("DllMain",):
                findings.append(ExportFinding(
                    name=export, category="Notable Export",
                    description=desc, lpe_note="",
                ))
                break

    if is_com_server and not is_service_dll:
        findings.insert(0, ExportFinding(
            name="[COM IN-PROC SERVER]", category="Binary Type",
            description="This DLL is a COM in-process server (DllGetClassObject export)",
            lpe_note="Check CLSID registration: if LaunchPermission allows standard users and "
                     "server runs elevated = EoP via COM activation",
        ))

    if is_service_dll:
        svchost = "svchostpushserviceglobals" in export_set
        findings.insert(0, ExportFinding(
            name="[SERVICE DLL]", category="Binary Type",
            description=f"This DLL is a {'svchost-hosted ' if svchost else ''}Windows service",
            lpe_note="Service DLLs run as SYSTEM/LocalService/NetworkService. "
                     "All RPC/pipe/COM endpoints are high-value LPE targets.",
        ))

    return findings
