"""Import analyzer — flags dangerous API imports by category."""

from dataclasses import dataclass, field
from typing import List, Dict
from ..loader import PEInfo
from ..apidb import lookup, ApiEntry, Category, Severity


@dataclass
class ImportFinding:
    api: ApiEntry
    dll: str
    ordinal: bool = False


def analyze(pe_info: PEInfo) -> List[ImportFinding]:
    findings = []

    for dll_name, functions in pe_info.imports.items():
        for func_name in functions:
            is_ordinal = func_name.startswith("ordinal_")
            entry = lookup(func_name)
            if entry:
                findings.append(ImportFinding(
                    api=entry,
                    dll=dll_name,
                    ordinal=is_ordinal,
                ))

    findings.sort(key=lambda f: list(Severity).index(f.api.severity))
    return findings


def summarize_by_category(findings: List[ImportFinding]) -> Dict[Category, List[ImportFinding]]:
    by_cat: Dict[Category, List[ImportFinding]] = {}
    for f in findings:
        by_cat.setdefault(f.api.category, []).append(f)
    return by_cat
