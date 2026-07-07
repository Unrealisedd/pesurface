"""
Dangerous Windows API database for LPE attack surface analysis.

Each entry maps an API name to its risk category, severity, and a short
description of why it matters from an attacker's perspective.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    DLL_LOADING = "dll_loading"
    PROCESS_CREATION = "process_creation"
    IMPERSONATION = "impersonation"
    TOKEN_MANIPULATION = "token_manipulation"
    NAMED_PIPE = "named_pipe"
    FILE_OPERATION = "file_operation"
    REGISTRY = "registry"
    SERVICE_CONTROL = "service_control"
    COM = "com"
    CREDENTIAL = "credential"
    MEMORY = "memory"
    PRIVILEGE = "privilege"
    DRIVER = "driver"
    NETWORK = "network"
    SECURITY_DESCRIPTOR = "security_descriptor"


@dataclass
class ApiEntry:
    name: str
    category: Category
    severity: Severity
    description: str
    lpe_relevance: str


DANGEROUS_APIS: Dict[str, ApiEntry] = {}

def _add(name: str, cat: Category, sev: Severity, desc: str, lpe: str):
    DANGEROUS_APIS[name.lower()] = ApiEntry(name, cat, sev, desc, lpe)
    # Also register the W/A/Ex variants
    for suffix in ("A", "W", "Ex", "ExA", "ExW"):
        variant = name + suffix
        DANGEROUS_APIS[variant.lower()] = ApiEntry(variant, cat, sev, desc, lpe)

def _add_exact(name: str, cat: Category, sev: Severity, desc: str, lpe: str):
    DANGEROUS_APIS[name.lower()] = ApiEntry(name, cat, sev, desc, lpe)


# ── DLL Loading ──────────────────────────────────────────────────────
_add("LoadLibrary", Category.DLL_LOADING, Severity.HIGH,
     "Loads DLL using standard search order",
     "DLL hijack if called without full path or LOAD_LIBRARY_SEARCH_SYSTEM32")

_add("LoadLibraryEx", Category.DLL_LOADING, Severity.MEDIUM,
     "Loads DLL with flags — check for LOAD_LIBRARY_SEARCH_SYSTEM32",
     "Safe only if dwFlags includes LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800)")

_add_exact("LoadPackagedLibrary", Category.DLL_LOADING, Severity.LOW,
     "Loads DLL from app package", "Limited to packaged apps")

_add_exact("AddDllDirectory", Category.DLL_LOADING, Severity.MEDIUM,
     "Adds directory to DLL search order",
     "If attacker controls the added directory, DLL hijack is possible")

_add_exact("SetDllDirectoryW", Category.DLL_LOADING, Severity.MEDIUM,
     "Sets DLL search directory",
     "Attacker-controlled directory = DLL plant")

_add_exact("SetDllDirectoryA", Category.DLL_LOADING, Severity.MEDIUM,
     "Sets DLL search directory",
     "Attacker-controlled directory = DLL plant")


# ── Process Creation ─────────────────────────────────────────────────
_add("CreateProcess", Category.PROCESS_CREATION, Severity.HIGH,
     "Creates a new process",
     "Command injection if lpCommandLine is attacker-influenced; "
     "token theft if called with stolen handle")

_add_exact("CreateProcessAsUserW", Category.PROCESS_CREATION, Severity.CRITICAL,
     "Creates process under different user token",
     "Direct privilege escalation if token is SYSTEM or elevated")

_add_exact("CreateProcessAsUserA", Category.PROCESS_CREATION, Severity.CRITICAL,
     "Creates process under different user token",
     "Direct privilege escalation if token is SYSTEM or elevated")

_add_exact("CreateProcessWithLogonW", Category.PROCESS_CREATION, Severity.CRITICAL,
     "Creates process with explicit credentials",
     "Credential exposure; can spawn elevated processes")

_add_exact("CreateProcessWithTokenW", Category.PROCESS_CREATION, Severity.CRITICAL,
     "Creates process with duplicated token",
     "Direct privilege escalation with SYSTEM token")

_add("ShellExecute", Category.PROCESS_CREATION, Severity.HIGH,
     "Opens/runs a file via shell",
     "Command injection if path is attacker-controlled")

_add_exact("WinExec", Category.PROCESS_CREATION, Severity.HIGH,
     "Runs a command (legacy)",
     "Command injection; no CreateProcess flags for mitigation")

_add_exact("system", Category.PROCESS_CREATION, Severity.CRITICAL,
     "CRT system() — runs command via cmd.exe",
     "Trivial command injection if argument is attacker-influenced")

_add_exact("_wsystem", Category.PROCESS_CREATION, Severity.CRITICAL,
     "Wide-char CRT system()",
     "Trivial command injection if argument is attacker-influenced")

_add_exact("_popen", Category.PROCESS_CREATION, Severity.HIGH,
     "Opens pipe to command",
     "Command injection via cmd.exe")

_add_exact("_wpopen", Category.PROCESS_CREATION, Severity.HIGH,
     "Wide-char pipe to command",
     "Command injection via cmd.exe")


# ── Impersonation ────────────────────────────────────────────────────
_add_exact("ImpersonateNamedPipeClient", Category.IMPERSONATION, Severity.CRITICAL,
     "Impersonates the client of a named pipe",
     "Classic SYSTEM LPE: lure privileged client to connect, impersonate its token")

_add_exact("ImpersonateLoggedOnUser", Category.IMPERSONATION, Severity.HIGH,
     "Impersonates a logged-on user's token",
     "Privilege escalation if token belongs to higher-privilege account")

_add_exact("ImpersonateSelf", Category.IMPERSONATION, Severity.LOW,
     "Impersonates own token at specified level",
     "Usually benign; watch for SecurityDelegation level")

_add_exact("SetThreadToken", Category.IMPERSONATION, Severity.HIGH,
     "Assigns impersonation token to thread",
     "Elevation if token is SYSTEM; check RevertToSelf pairing")

_add_exact("RevertToSelf", Category.IMPERSONATION, Severity.INFO,
     "Reverts thread to process token",
     "If missing after impersonation = runs remaining code as impersonated user")

_add_exact("RpcImpersonateClient", Category.IMPERSONATION, Severity.CRITICAL,
     "Impersonates RPC caller",
     "If RPC endpoint is reachable by standard user, SYSTEM impersonation")

_add_exact("CoImpersonateClient", Category.IMPERSONATION, Severity.CRITICAL,
     "Impersonates COM caller",
     "COM server running as SYSTEM + missing cloaking = token steal")


# ── Token Manipulation ──────────────────────────────────────────────
_add_exact("OpenProcessToken", Category.TOKEN_MANIPULATION, Severity.MEDIUM,
     "Opens a process's access token",
     "Token duplication chain; check desired access for TOKEN_DUPLICATE")

_add_exact("OpenThreadToken", Category.TOKEN_MANIPULATION, Severity.MEDIUM,
     "Opens a thread's impersonation token",
     "Part of token theft chains")

_add("DuplicateToken", Category.TOKEN_MANIPULATION, Severity.HIGH,
     "Duplicates an access token",
     "Creates usable copy of SYSTEM token for CreateProcessAsUser")

_add_exact("AdjustTokenPrivileges", Category.TOKEN_MANIPULATION, Severity.HIGH,
     "Enables/disables token privileges",
     "Enabling SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege")

_add_exact("LookupPrivilegeValueW", Category.TOKEN_MANIPULATION, Severity.INFO,
     "Resolves privilege name to LUID",
     "Indicates the binary checks/uses specific privileges")

_add_exact("LookupPrivilegeValueA", Category.TOKEN_MANIPULATION, Severity.INFO,
     "Resolves privilege name to LUID",
     "Indicates the binary checks/uses specific privileges")

_add_exact("NtSetInformationToken", Category.TOKEN_MANIPULATION, Severity.HIGH,
     "Native API to modify token",
     "Can modify token integrity level, session ID, or privileges")


# ── Named Pipes ──────────────────────────────────────────────────────
_add("CreateNamedPipe", Category.NAMED_PIPE, Severity.HIGH,
     "Creates a named pipe server",
     "If DACL allows Everyone and impersonation is used = SYSTEM LPE")

_add_exact("ConnectNamedPipe", Category.NAMED_PIPE, Severity.MEDIUM,
     "Waits for client connection on pipe",
     "Paired with ImpersonateNamedPipeClient = impersonation primitive")

_add_exact("CallNamedPipeW", Category.NAMED_PIPE, Severity.LOW,
     "Connects to and writes to named pipe",
     "If pipe name is attacker-controlled = pipe squatting")

_add_exact("CallNamedPipeA", Category.NAMED_PIPE, Severity.LOW,
     "Connects to and writes to named pipe",
     "If pipe name is attacker-controlled = pipe squatting")

_add_exact("WaitNamedPipeW", Category.NAMED_PIPE, Severity.LOW,
     "Waits for pipe to become available",
     "Indicates pipe client behavior; check for race conditions")


# ── File Operations ──────────────────────────────────────────────────
_add("CreateFile", Category.FILE_OPERATION, Severity.MEDIUM,
     "Opens or creates a file/device",
     "TOCTOU races; junction/symlink following; missing OPEN_EXISTING")

_add("MoveFile", Category.FILE_OPERATION, Severity.HIGH,
     "Moves/renames a file",
     "Symlink/junction attack if destination is in privileged directory")

_add_exact("MoveFileExW", Category.FILE_OPERATION, Severity.HIGH,
     "Moves file with flags",
     "MOVEFILE_REPLACE_EXISTING in privileged dir = arbitrary write")

_add_exact("MoveFileExA", Category.FILE_OPERATION, Severity.HIGH,
     "Moves file with flags",
     "MOVEFILE_REPLACE_EXISTING in privileged dir = arbitrary write")

_add("CopyFile", Category.FILE_OPERATION, Severity.MEDIUM,
     "Copies a file",
     "If destination is privileged dir and source is attacker-controlled")

_add("DeleteFile", Category.FILE_OPERATION, Severity.MEDIUM,
     "Deletes a file",
     "Arbitrary delete via junction if path traversal is possible")

_add("ReplaceFile", Category.FILE_OPERATION, Severity.HIGH,
     "Atomically replaces a file",
     "Powerful arbitrary-write primitive if paths are controllable")

_add("WriteFile", Category.FILE_OPERATION, Severity.LOW,
     "Writes data to file/device",
     "Check what handle it writes to; device writes = IOCTL-like")

_add("SetFileAttributes", Category.FILE_OPERATION, Severity.LOW,
     "Sets file attributes",
     "Can remove read-only before overwrite")

_add_exact("CreateDirectoryW", Category.FILE_OPERATION, Severity.LOW,
     "Creates a directory",
     "Directory creation in privileged paths; DACL inheritance")

_add_exact("CreateDirectoryA", Category.FILE_OPERATION, Severity.LOW,
     "Creates a directory",
     "Directory creation in privileged paths; DACL inheritance")

_add_exact("CreateHardLinkW", Category.FILE_OPERATION, Severity.HIGH,
     "Creates a hard link",
     "Hardlink to privileged file + later overwrite = arbitrary write")

_add_exact("CreateSymbolicLinkW", Category.FILE_OPERATION, Severity.HIGH,
     "Creates a symbolic link",
     "Symlink attacks in privileged services = arbitrary file operations")

_add_exact("NtCreateFile", Category.FILE_OPERATION, Severity.MEDIUM,
     "Native file open",
     "May bypass some Win32 path validation")

_add_exact("NtSetInformationFile", Category.FILE_OPERATION, Severity.MEDIUM,
     "Native file metadata change",
     "FileRenameInformation = cross-volume move, FileLinkInformation = hardlink")


# ── Registry ─────────────────────────────────────────────────────────
_add("RegCreateKey", Category.REGISTRY, Severity.MEDIUM,
     "Creates or opens a registry key",
     "If writing to HKLM or service keys from user context = persistence/escalation")

_add("RegSetValue", Category.REGISTRY, Severity.MEDIUM,
     "Sets a registry value",
     "Modifying service ImagePath, COM InProcServer32, or Run keys")

_add("RegOpenKey", Category.REGISTRY, Severity.LOW,
     "Opens a registry key",
     "Check if reading sensitive keys (LSA secrets, SAM, service configs)")

_add_exact("RegSetKeyValueW", Category.REGISTRY, Severity.MEDIUM,
     "Sets registry key value",
     "Same risks as RegSetValue")

_add_exact("RegDeleteKeyW", Category.REGISTRY, Severity.MEDIUM,
     "Deletes a registry key",
     "Deleting security configurations")

_add_exact("RegDeleteValueW", Category.REGISTRY, Severity.LOW,
     "Deletes a registry value",
     "May remove security settings")


# ── Service Control ──────────────────────────────────────────────────
_add("CreateService", Category.SERVICE_CONTROL, Severity.CRITICAL,
     "Registers a new Windows service",
     "If reachable = direct code execution as SYSTEM via service binary")

_add("ChangeServiceConfig", Category.SERVICE_CONTROL, Severity.CRITICAL,
     "Modifies service configuration",
     "Changing ImagePath = arbitrary code execution as service account")

_add("StartService", Category.SERVICE_CONTROL, Severity.HIGH,
     "Starts a Windows service",
     "If combined with ChangeServiceConfig = controlled SYSTEM execution")

_add_exact("OpenServiceW", Category.SERVICE_CONTROL, Severity.LOW,
     "Opens a service handle",
     "Check requested access rights for SERVICE_CHANGE_CONFIG")

_add_exact("OpenServiceA", Category.SERVICE_CONTROL, Severity.LOW,
     "Opens a service handle",
     "Check requested access rights for SERVICE_CHANGE_CONFIG")

_add_exact("OpenSCManagerW", Category.SERVICE_CONTROL, Severity.LOW,
     "Opens service control manager",
     "Indicates service manipulation code")

_add_exact("OpenSCManagerA", Category.SERVICE_CONTROL, Severity.LOW,
     "Opens service control manager",
     "Indicates service manipulation code")

_add_exact("ControlService", Category.SERVICE_CONTROL, Severity.MEDIUM,
     "Sends control code to service",
     "SERVICE_CONTROL_STOP + restart with modified config")


# ── COM ──────────────────────────────────────────────────────────────
_add_exact("CoCreateInstance", Category.COM, Severity.MEDIUM,
     "Creates COM object instance",
     "Cross-privilege COM activation; check CLSID for elevated servers")

_add_exact("CoCreateInstanceEx", Category.COM, Severity.MEDIUM,
     "Creates COM object (extended)",
     "Remote/cross-session activation")

_add_exact("DllGetClassObject", Category.COM, Severity.MEDIUM,
     "COM class factory entry point (export)",
     "This binary IS a COM server; check what CLSIDs it serves")

_add_exact("CoRegisterClassObject", Category.COM, Severity.HIGH,
     "Registers a COM class in the running object table",
     "COM server registration; check activation permissions")

_add_exact("DllRegisterServer", Category.COM, Severity.LOW,
     "Self-registration entry point",
     "Writes COM registration to registry")

_add_exact("CoGetClassObject", Category.COM, Severity.MEDIUM,
     "Gets COM class factory",
     "COM activation; check privilege level of server")


# ── Credentials ──────────────────────────────────────────────────────
_add_exact("CredReadW", Category.CREDENTIAL, Severity.HIGH,
     "Reads stored credential",
     "Credential theft from Windows credential manager")

_add_exact("CredReadA", Category.CREDENTIAL, Severity.HIGH,
     "Reads stored credential",
     "Credential theft from Windows credential manager")

_add_exact("CredWriteW", Category.CREDENTIAL, Severity.MEDIUM,
     "Stores credential",
     "May store plaintext or weakly protected secrets")

_add_exact("CryptUnprotectData", Category.CREDENTIAL, Severity.HIGH,
     "Decrypts DPAPI-protected data",
     "If called by SYSTEM service = decrypts any user's DPAPI blobs")

_add_exact("LogonUserW", Category.CREDENTIAL, Severity.CRITICAL,
     "Authenticates user credentials",
     "If credentials are hardcoded or attacker-supplied = account takeover")

_add_exact("LogonUserA", Category.CREDENTIAL, Severity.CRITICAL,
     "Authenticates user credentials",
     "If credentials are hardcoded or attacker-supplied = account takeover")

_add_exact("LsaLogonUser", Category.CREDENTIAL, Severity.CRITICAL,
     "LSA logon interface",
     "Direct authentication; custom auth packages")


# ── Driver / Kernel ──────────────────────────────────────────────────
_add_exact("IoCreateDevice", Category.DRIVER, Severity.HIGH,
     "Creates a device object",
     "Check device name and DACL; world-accessible = kernel attack surface")

_add_exact("IoCreateDeviceSecure", Category.DRIVER, Severity.MEDIUM,
     "Creates device with security descriptor",
     "Better than IoCreateDevice but check the SDDL string")

_add_exact("IoCreateSymbolicLink", Category.DRIVER, Severity.MEDIUM,
     "Creates device symlink in \\DosDevices",
     "Makes driver accessible from user mode")

_add_exact("MmMapLockedPagesSpecifyCache", Category.DRIVER, Severity.CRITICAL,
     "Maps locked pages to user/kernel space",
     "If UserMode mapping = arbitrary kernel read/write from userland")

_add_exact("ZwMapViewOfSection", Category.DRIVER, Severity.HIGH,
     "Maps section into process address space",
     "Kernel-to-user memory mapping; check access")

_add_exact("ProbeForRead", Category.DRIVER, Severity.INFO,
     "Validates user buffer for read",
     "Good sign — the driver validates input buffers")

_add_exact("ProbeForWrite", Category.DRIVER, Severity.INFO,
     "Validates user buffer for write",
     "Good sign — the driver validates output buffers")

_add_exact("MmProbeAndLockPages", Category.DRIVER, Severity.MEDIUM,
     "Probes and locks user pages",
     "Check for proper exception handling")

_add_exact("SeAccessCheck", Category.DRIVER, Severity.INFO,
     "Performs access check in kernel",
     "Good sign — driver checks caller permissions")

_add_exact("DeviceIoControl", Category.DRIVER, Severity.MEDIUM,
     "Sends IOCTL to driver (user-mode side)",
     "Indicates this binary communicates with a driver")


# ── Security Descriptors ─────────────────────────────────────────────
_add_exact("SetSecurityDescriptorDacl", Category.SECURITY_DESCRIPTOR, Severity.MEDIUM,
     "Sets DACL on security descriptor",
     "Check if NULL DACL (Everyone full access) is set")

_add_exact("ConvertStringSecurityDescriptorToSecurityDescriptorW",
     Category.SECURITY_DESCRIPTOR, Severity.MEDIUM,
     "Parses SDDL string to security descriptor",
     "Extract the SDDL string to check permissions")

_add_exact("SetKernelObjectSecurity", Category.SECURITY_DESCRIPTOR, Severity.MEDIUM,
     "Sets security on kernel object",
     "Weakening object security = privilege escalation")

_add_exact("SetNamedSecurityInfoW", Category.SECURITY_DESCRIPTOR, Severity.MEDIUM,
     "Sets security on named object",
     "Modifying DACLs on files/registry/services")

_add_exact("InitializeSecurityDescriptor", Category.SECURITY_DESCRIPTOR, Severity.INFO,
     "Initializes a security descriptor",
     "Check if followed by SetSecurityDescriptorDacl with NULL")


# ── Network ──────────────────────────────────────────────────────────
_add_exact("bind", Category.NETWORK, Severity.LOW,
     "Binds socket to address",
     "Network listener; check if 0.0.0.0 or localhost")

_add_exact("listen", Category.NETWORK, Severity.LOW,
     "Listens for connections",
     "Opens network attack surface")

_add_exact("HttpAddUrl", Category.NETWORK, Severity.MEDIUM,
     "Registers HTTP URL prefix",
     "HTTP.sys listener; check ACL on URL reservation")

_add_exact("RpcServerRegisterIf", Category.NETWORK, Severity.HIGH,
     "Registers RPC interface",
     "RPC endpoint; check authentication and access")

_add_exact("RpcServerRegisterIf2", Category.NETWORK, Severity.HIGH,
     "Registers RPC interface (v2)",
     "Check security callback parameter")

_add_exact("RpcServerRegisterIf3", Category.NETWORK, Severity.HIGH,
     "Registers RPC interface (v3)",
     "Check security callback and flags")

_add_exact("RpcServerRegisterIfEx", Category.NETWORK, Severity.HIGH,
     "Registers RPC interface (extended)",
     "Check RPC_IF_ALLOW_LOCAL_ONLY flag and security callback")

_add_exact("RpcServerUseProtseqEpW", Category.NETWORK, Severity.MEDIUM,
     "Sets RPC protocol sequence and endpoint",
     "Check ncalrpc (local) vs ncacn_np (named pipe) vs ncacn_ip_tcp (network)")

_add_exact("RpcServerListen", Category.NETWORK, Severity.LOW,
     "Starts RPC server listening",
     "Confirms RPC server is active")


def lookup(api_name: str) -> ApiEntry | None:
    return DANGEROUS_APIS.get(api_name.lower())


def get_categories() -> List[Category]:
    return list(Category)
