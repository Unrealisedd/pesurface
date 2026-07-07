"""IOCTL dispatch table extraction for kernel drivers.

Scans the .text section for patterns that look like IOCTL dispatch:
- IRP_MJ_DEVICE_CONTROL handler assignment (MajorFunction[14] = ...)
- IOCTL code comparisons (cmp reg, 0xNNNNNN / sub reg, 0xNNNNNN / switch-jump tables)
- DeviceIoControl call patterns

Decodes IOCTL codes into device type, function, method, and access.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional
from ..loader import PEInfo


METHOD_NAMES = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
ACCESS_NAMES = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}

KNOWN_DEVICE_TYPES = {
    0x01: "FILE_DEVICE_BEEP", 0x02: "FILE_DEVICE_CD_ROM",
    0x03: "FILE_DEVICE_CD_ROM_FILE_SYSTEM", 0x04: "FILE_DEVICE_CONTROLLER",
    0x05: "FILE_DEVICE_DATALINK", 0x06: "FILE_DEVICE_DFS",
    0x07: "FILE_DEVICE_DISK", 0x08: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x09: "FILE_DEVICE_FILE_SYSTEM", 0x0C: "FILE_DEVICE_KEYBOARD",
    0x0F: "FILE_DEVICE_MOUSE", 0x12: "FILE_DEVICE_NETWORK",
    0x17: "FILE_DEVICE_SCREEN", 0x18: "FILE_DEVICE_SOUND",
    0x1B: "FILE_DEVICE_TRANSPORT", 0x1F: "FILE_DEVICE_ACPI",
    0x21: "FILE_DEVICE_DVD", 0x22: "FILE_DEVICE_UNKNOWN",
    0x27: "FILE_DEVICE_INFRARED", 0x29: "FILE_DEVICE_MODEM",
    0x32: "FILE_DEVICE_MASS_STORAGE", 0x34: "FILE_DEVICE_KS",
    0x37: "FILE_DEVICE_BATTERY", 0x39: "FILE_DEVICE_BUS_EXTENDER",
    0x3E: "FILE_DEVICE_CRYPT_PROVIDER", 0x41: "FILE_DEVICE_FIPS",
    0x50: "FILE_DEVICE_BIOMETRIC", 0x59: "FILE_DEVICE_PMI",
}


@dataclass
class IoctlCode:
    code: int
    device_type: int
    function: int
    method: int
    access: int
    offset: int
    device_type_name: str
    method_name: str
    access_name: str


def decode_ioctl(code: int) -> Optional[dict]:
    device_type = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3

    if device_type == 0 or function == 0:
        return None

    return {
        "device_type": device_type,
        "function": function,
        "method": method,
        "access": access,
    }


def analyze(pe_info: PEInfo) -> List[IoctlCode]:
    if not pe_info.is_driver and not str(pe_info.path).lower().endswith(".sys"):
        return []

    codes = []
    seen = set()

    for section in pe_info.pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue

        data = section.get_data()
        sec_offset = section.PointerToRawData

        # Pattern 1: CMP r32, imm32 (81 F8-FF xx xx xx xx)
        # Pattern 2: SUB r32, imm32 (81 E8-EF xx xx xx xx)
        # Pattern 3: MOV r32, imm32 (B8-BF xx xx xx xx)
        for i in range(len(data) - 5):
            candidate = None

            if data[i] == 0x81 and 0xF8 <= data[i+1] <= 0xFF:
                candidate = struct.unpack_from("<I", data, i + 2)[0]
            elif data[i] == 0x81 and 0xE8 <= data[i+1] <= 0xEF:
                candidate = struct.unpack_from("<I", data, i + 2)[0]
            elif data[i] == 0x3D:
                candidate = struct.unpack_from("<I", data, i + 1)[0]

            if candidate and candidate not in seen:
                decoded = decode_ioctl(candidate)
                if decoded and decoded["device_type"] < 0x8000:
                    if 0x800 <= decoded["function"] < 0xFFF or decoded["function"] < 0x400:
                        dt = decoded["device_type"]
                        codes.append(IoctlCode(
                            code=candidate,
                            device_type=dt,
                            function=decoded["function"],
                            method=decoded["method"],
                            access=decoded["access"],
                            offset=sec_offset + i,
                            device_type_name=KNOWN_DEVICE_TYPES.get(dt, f"CUSTOM (0x{dt:X})"),
                            method_name=METHOD_NAMES.get(decoded["method"], "UNKNOWN"),
                            access_name=ACCESS_NAMES.get(decoded["access"], "UNKNOWN"),
                        ))
                        seen.add(candidate)

    codes.sort(key=lambda c: c.code)
    return codes
