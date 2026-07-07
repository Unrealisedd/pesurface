"""PE file loader — wraps pefile with convenience methods."""

import pefile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


@dataclass
class PEInfo:
    path: Path
    pe: pefile.PE
    is_dll: bool = False
    is_driver: bool = False
    is_exe: bool = False
    is_64bit: bool = False
    imports: Dict[str, List[str]] = field(default_factory=dict)
    exports: List[str] = field(default_factory=list)
    sections: List[dict] = field(default_factory=list)


DRIVER_SUBSYSTEMS = {
    pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS: None,
    1: None,  # IMAGE_SUBSYSTEM_NATIVE — kernel driver
}


def load(path: str) -> PEInfo:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    pe = pefile.PE(str(p), fast_load=False)

    info = PEInfo(path=p, pe=pe)
    info.is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
    info.is_dll = bool(pe.FILE_HEADER.Characteristics & pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"])
    info.is_driver = pe.OPTIONAL_HEADER.Subsystem == 1  # IMAGE_SUBSYSTEM_NATIVE

    suffix = p.suffix.lower()
    if suffix == ".sys":
        info.is_driver = True
    info.is_exe = suffix == ".exe" and not info.is_dll

    # Parse imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="replace"))
                elif imp.ordinal:
                    funcs.append(f"ordinal_{imp.ordinal}")
            info.imports[dll_name] = funcs

    # Parse delayed imports
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace") + " (delay)"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="replace"))
                elif imp.ordinal:
                    funcs.append(f"ordinal_{imp.ordinal}")
            info.imports[dll_name] = funcs

    # Parse exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                info.exports.append(exp.name.decode("utf-8", errors="replace"))
            elif exp.ordinal:
                info.exports.append(f"ordinal_{exp.ordinal}")

    # Section info
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
        info.sections.append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "characteristics": section.Characteristics,
            "executable": bool(section.Characteristics & 0x20000000),
            "writable": bool(section.Characteristics & 0x80000000),
            "readable": bool(section.Characteristics & 0x40000000),
        })

    return info
