"""PE metadata analysis — security features, signing, characteristics."""

from dataclasses import dataclass
from typing import Optional
from ..loader import PEInfo


@dataclass
class MetadataFindings:
    arch: str
    binary_type: str
    subsystem: str
    aslr: bool
    dep: bool
    cfg: bool
    high_entropy_aslr: bool
    force_integrity: bool
    no_seh: bool
    guard_cf: bool
    signed: bool
    entry_point: int
    image_base: int
    linker_version: str


def analyze(pe_info: PEInfo) -> MetadataFindings:
    pe = pe_info.pe
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    dll_chars = oh.DllCharacteristics if hasattr(oh, "DllCharacteristics") else 0

    # Architecture
    machine = fh.Machine
    if machine == 0x8664:
        arch = "x86_64"
    elif machine == 0x14c:
        arch = "x86"
    elif machine == 0xAA64:
        arch = "ARM64"
    else:
        arch = f"unknown (0x{machine:x})"

    # Binary type
    if pe_info.is_driver:
        binary_type = "Kernel Driver"
    elif pe_info.is_dll:
        binary_type = "DLL"
    elif pe_info.is_exe:
        binary_type = "Executable"
    else:
        binary_type = "Unknown"

    # Subsystem
    subsys_map = {
        0: "Unknown", 1: "Native (Driver)", 2: "Windows GUI",
        3: "Windows Console", 5: "OS/2 Console", 7: "POSIX Console",
        9: "Windows CE", 10: "EFI Application", 14: "Xbox",
    }
    subsystem = subsys_map.get(oh.Subsystem, f"Unknown ({oh.Subsystem})")

    return MetadataFindings(
        arch=arch,
        binary_type=binary_type,
        subsystem=subsystem,
        aslr=bool(dll_chars & 0x0040),          # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        dep=bool(dll_chars & 0x0100),            # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        cfg=bool(dll_chars & 0x4000),            # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        high_entropy_aslr=bool(dll_chars & 0x0020),  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        force_integrity=bool(dll_chars & 0x0080),     # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
        no_seh=bool(dll_chars & 0x0400),               # IMAGE_DLLCHARACTERISTICS_NO_SEH
        guard_cf=bool(dll_chars & 0x4000),
        signed=hasattr(pe, "DIRECTORY_ENTRY_SECURITY"),
        entry_point=oh.AddressOfEntryPoint,
        image_base=oh.ImageBase,
        linker_version=f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
    )
