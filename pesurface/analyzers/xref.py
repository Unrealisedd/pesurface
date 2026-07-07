"""Cross-reference imports with strings.

Heuristic matcher: for each dangerous import, find strings in the same
binary that are likely arguments (e.g., LoadLibrary + DLL names,
CreateNamedPipe + pipe paths, RegSetValue + registry paths).
"""

from dataclasses import dataclass
from typing import List
from .imports import ImportFinding
from .strings import StringFinding, StringType
from ..apidb import Category


@dataclass
class XrefFinding:
    api_name: str
    api_category: str
    string_value: str
    string_type: str
    note: str


# Maps API categories to the string types that are likely their arguments
CATEGORY_STRING_MAP = {
    Category.DLL_LOADING: [
        (StringType.FILE_PATH, "Potential DLL path argument"),
    ],
    Category.NAMED_PIPE: [
        (StringType.NAMED_PIPE, "Pipe name used by this binary"),
    ],
    Category.REGISTRY: [
        (StringType.REGISTRY_PATH, "Registry path operated on"),
    ],
    Category.FILE_OPERATION: [
        (StringType.FILE_PATH, "File path for file operation"),
        (StringType.UNC_PATH, "UNC path — possible remote file operation"),
    ],
    Category.PROCESS_CREATION: [
        (StringType.COMMAND, "Command string for process creation"),
        (StringType.FILE_PATH, "Executable path for process creation"),
    ],
    Category.COM: [
        (StringType.CLSID, "CLSID for COM activation"),
    ],
    Category.SECURITY_DESCRIPTOR: [
        (StringType.SDDL, "SDDL descriptor string"),
    ],
    Category.NETWORK: [
        (StringType.NAMED_PIPE, "RPC endpoint pipe name"),
        (StringType.URL, "Network endpoint URL"),
    ],
    Category.CREDENTIAL: [
        (StringType.REGISTRY_PATH, "Credential storage path"),
    ],
}

# DLL name patterns to look for in strings when LoadLibrary imports exist
DLL_PATTERN_SUFFIXES = (".dll", ".DLL", ".drv", ".cpl", ".ocx")


def analyze(
    import_findings: List[ImportFinding],
    string_findings: List[StringFinding],
) -> List[XrefFinding]:
    results = []
    seen = set()

    categories_present = set(f.api.category for f in import_findings)

    # String type index
    by_type = {}
    for sf in string_findings:
        by_type.setdefault(sf.string_type, []).append(sf)

    for cat in categories_present:
        mappings = CATEGORY_STRING_MAP.get(cat, [])
        for stype, note in mappings:
            for sf in by_type.get(stype, []):
                key = (cat.value, sf.value)
                if key not in seen:
                    seen.add(key)
                    results.append(XrefFinding(
                        api_name=_get_api_for_cat(cat, import_findings),
                        api_category=cat.value,
                        string_value=sf.value,
                        string_type=stype.value,
                        note=note,
                    ))

    # Special case: LoadLibrary + any string ending in .dll
    if Category.DLL_LOADING in categories_present:
        for sf in string_findings:
            if any(sf.value.endswith(s) for s in DLL_PATTERN_SUFFIXES):
                key = ("dll_load_xref", sf.value)
                if key not in seen:
                    seen.add(key)
                    results.append(XrefFinding(
                        api_name="LoadLibrary*",
                        api_category="dll_loading",
                        string_value=sf.value,
                        string_type="dll_name",
                        note="DLL name string — potential LoadLibrary argument",
                    ))

    return results


def _get_api_for_cat(cat, findings):
    for f in findings:
        if f.api.category == cat:
            return f.api.name
    return cat.value
