"""String extraction — finds attack-surface-relevant strings in PE sections."""

import re
import struct
from dataclasses import dataclass
from typing import List
from enum import Enum
from ..loader import PEInfo


class StringType(Enum):
    NAMED_PIPE = "named_pipe"
    REGISTRY_PATH = "registry_path"
    UNC_PATH = "unc_path"
    FILE_PATH = "file_path"
    URL = "url"
    CLSID = "clsid"
    SDDL = "sddl"
    COMMAND = "command"
    PRIVILEGE = "privilege"
    SERVICE_NAME = "service_name"
    ENVIRONMENT_VAR = "environment_var"


@dataclass
class StringFinding:
    value: str
    string_type: StringType
    offset: int
    section: str
    encoding: str  # "ascii" or "utf-16le"


PATTERNS = {
    StringType.NAMED_PIPE: [
        re.compile(r"\\\\\.\\pipe\\[^\x00\s\"\']{2,}", re.IGNORECASE),
        re.compile(r"\\\\\?\\pipe\\[^\x00\s\"\']{2,}", re.IGNORECASE),
    ],
    StringType.REGISTRY_PATH: [
        re.compile(r"(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT)"
                   r"\\[^\x00\s\"\']{4,}", re.IGNORECASE),
        re.compile(r"(?:SOFTWARE|SYSTEM|CurrentControlSet)\\[^\x00\s\"\']{4,}", re.IGNORECASE),
    ],
    StringType.UNC_PATH: [
        re.compile(r"\\\\[a-zA-Z0-9_.%-]+\\[^\x00\s\"\']{2,}"),
    ],
    StringType.FILE_PATH: [
        re.compile(r"[A-Z]:\\[^\x00\s\"\']{4,}"),
        re.compile(r"%[A-Za-z_]+%\\[^\x00\s\"\']{3,}"),
    ],
    StringType.URL: [
        re.compile(r"https?://[^\x00\s\"\']{4,}"),
    ],
    StringType.CLSID: [
        re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"),
    ],
    StringType.SDDL: [
        re.compile(r"[DO]:[A-Z]*(?:\([^)]+\))+"),
    ],
    StringType.COMMAND: [
        re.compile(r"(?:cmd\.exe|powershell\.exe|cmd\s+/[ck]|powershell\s+-)", re.IGNORECASE),
    ],
    StringType.PRIVILEGE: [
        re.compile(r"Se[A-Z][a-zA-Z]+Privilege"),
    ],
    StringType.SERVICE_NAME: [
        re.compile(r"(?:SERVICE_NAME|ServiceName)\s*[:=]\s*[^\x00\s\"\']+", re.IGNORECASE),
    ],
    StringType.ENVIRONMENT_VAR: [
        re.compile(r"%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|USERPROFILE|"
                   r"PROGRAMFILES|PROGRAMFILES\(X86\)|WINDIR|SYSTEMROOT|PATH|"
                   r"COMSPEC|PUBLIC)%", re.IGNORECASE),
    ],
}


def _extract_ascii(data: bytes, min_len: int = 6) -> List[tuple]:
    """Extract ASCII strings with their offsets."""
    results = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append(("".join(current), start))
            current = []
    if len(current) >= min_len:
        results.append(("".join(current), start))
    return results


def _extract_utf16(data: bytes, min_len: int = 6) -> List[tuple]:
    """Extract UTF-16LE strings with their offsets."""
    results = []
    current = []
    start = 0
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7f:
            if not current:
                start = i
            current.append(chr(lo))
        else:
            if len(current) >= min_len:
                results.append(("".join(current), start))
            current = []
    if len(current) >= min_len:
        results.append(("".join(current), start))
    return results


def analyze(pe_info: PEInfo) -> List[StringFinding]:
    findings = []
    seen = set()

    for section in pe_info.pe.sections:
        sec_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
        data = section.get_data()
        sec_offset = section.PointerToRawData

        for encoding, extractor in [("ascii", _extract_ascii), ("utf-16le", _extract_utf16)]:
            strings = extractor(data)
            for s, offset in strings:
                for stype, patterns in PATTERNS.items():
                    for pattern in patterns:
                        if pattern.search(s):
                            key = (s, stype)
                            if key not in seen:
                                seen.add(key)
                                findings.append(StringFinding(
                                    value=s,
                                    string_type=stype,
                                    offset=sec_offset + offset,
                                    section=sec_name,
                                    encoding=encoding,
                                ))
                            break

    return findings
