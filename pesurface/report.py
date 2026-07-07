"""Report output — color terminal and JSON export."""

import json
import sys
from typing import List, Optional

from .loader import PEInfo
from .analyzers.metadata import MetadataFindings
from .analyzers.imports import ImportFinding, summarize_by_category
from .analyzers.strings import StringFinding, StringType
from .analyzers.dllhijack import HijackCandidate
from .analyzers.ioctl import IoctlCode
from .analyzers.sddl import SddlFinding
from .analyzers.exports import ExportFinding
from .analyzers.xref import XrefFinding
from .analyzers.ghidra_analysis import GhidraFindings
from .apidb import Severity, Category


# ANSI color helpers
def _supports_color():
    if sys.platform == "win32":
        import os
        return os.environ.get("ANSICON") or os.environ.get("WT_SESSION") or "xterm" in os.environ.get("TERM", "")
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR = _supports_color()

def _c(code, text):
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def _bold(t):       return _c("1", t)
def _red(t):        return _c("91", t)
def _yellow(t):     return _c("93", t)
def _green(t):      return _c("92", t)
def _cyan(t):       return _c("96", t)
def _dim(t):        return _c("90", t)
def _magenta(t):    return _c("95", t)
def _white(t):      return _c("97", t)


_SEV_COLOR = {
    Severity.CRITICAL: _red,
    Severity.HIGH: _red,
    Severity.MEDIUM: _yellow,
    Severity.LOW: _cyan,
    Severity.INFO: _dim,
}

_SEV_ICON = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "! ",
    Severity.MEDIUM: "* ",
    Severity.LOW: "- ",
    Severity.INFO: "  ",
}


def _banner():
    lines = [
        "                          ___                ",
        "  _ __  ___  ___ _   _ _ / __| __ _  ___ ___ ",
        " | '_ \\/ _ \\/ __| | | | |__ \\/ _` |/ __/ _ \\\\",
        " | |_) |  __/\\__ \\ |_| | ___) | (_| | (_|  __/",
        " | .__/ \\___||___/\\__,_||____/ \\__,_|\\___\\___|",
        " |_|      PE Attack Surface Mapper",
    ]
    return "\n".join(_cyan(l) for l in lines)


def print_report(
    pe_info: PEInfo,
    metadata: MetadataFindings,
    import_findings: List[ImportFinding],
    string_findings: List[StringFinding],
    hijack_candidates: List[HijackCandidate],
    ioctl_codes: List[IoctlCode] = None,
    sddl_findings: List[SddlFinding] = None,
    export_findings: List[ExportFinding] = None,
    xref_findings: List[XrefFinding] = None,
    ghidra_findings: GhidraFindings = None,
):
    print(_banner())
    print()

    # Target info
    print(_bold("TARGET"))
    print(f"  Path:       {pe_info.path}")
    print(f"  Type:       {metadata.binary_type} ({metadata.arch})")
    print(f"  Subsystem:  {metadata.subsystem}")
    print(f"  Linker:     {metadata.linker_version}")
    print(f"  EntryPoint: 0x{metadata.entry_point:X}")
    print(f"  ImageBase:  0x{metadata.image_base:X}")
    print()

    # Security features
    print(_bold("HARDENING"))
    _check = lambda v: _green("ON") if v else _red("OFF")
    print(f"  ASLR:             {_check(metadata.aslr)}")
    print(f"  High-Entropy ASLR:{_check(metadata.high_entropy_aslr)}")
    print(f"  DEP/NX:           {_check(metadata.dep)}")
    print(f"  CFG:              {_check(metadata.cfg)}")
    print(f"  Force Integrity:  {_check(metadata.force_integrity)}")
    print(f"  SEH Protection:   {_check(not metadata.no_seh)}")
    print(f"  Authenticode:     {_check(metadata.signed)}")
    print()

    # Sections
    print(_bold("SECTIONS"))
    for s in pe_info.sections:
        perms = ""
        perms += "R" if s["readable"] else "-"
        perms += "W" if s["writable"] else "-"
        perms += "X" if s["executable"] else "-"
        name = s["name"].ljust(10)
        vsize = f"virt={s['virtual_size']:#x}".ljust(16)
        rsize = f"raw={s['raw_size']:#x}".ljust(15)
        print(f"  {name} {perms}  {vsize} {rsize}")
    print()

    # Dangerous imports
    if import_findings:
        print(_bold(f"DANGEROUS IMPORTS ({len(import_findings)})"))
        by_cat = summarize_by_category(import_findings)
        for cat in Category:
            if cat not in by_cat:
                continue
            findings = by_cat[cat]
            cat_label = cat.value.replace("_", " ").upper()
            print(f"\n  {_magenta(cat_label)}")
            for f in findings:
                sev_fn = _SEV_COLOR.get(f.api.severity, _dim)
                icon = _SEV_ICON.get(f.api.severity, "  ")
                dll_tag = _dim(f"[{f.dll}]")
                print(f"    {sev_fn(icon)} {_white(f.api.name)} {dll_tag}")
                print(f"       {_dim(f.api.description)}")
                if f.api.lpe_relevance:
                    print(f"       {_yellow('LPE:')} {f.api.lpe_relevance}")
        print()
    else:
        print(_dim("No dangerous API imports found."))
        print()

    # DLL hijack candidates
    if hijack_candidates:
        print(_bold(f"DLL HIJACK CANDIDATES ({len(hijack_candidates)})"))
        for h in hijack_candidates:
            delay_tag = _yellow(" [delay-loaded]") if h.is_delay_loaded else ""
            print(f"  {_red('!')} {_white(h.dll_name)}{delay_tag}")
            print(f"    {_dim(h.reason)}")
            if h.imported_functions:
                funcs = ", ".join(h.imported_functions[:5])
                if len(h.imported_functions) > 5:
                    funcs += f" (+{len(h.imported_functions)-5} more)"
                print(f"    Imports: {_dim(funcs)}")
        print()
    else:
        print(_dim("No DLL hijack candidates found."))
        print()

    # Strings
    if string_findings:
        print(_bold(f"INTERESTING STRINGS ({len(string_findings)})"))
        by_type = {}
        for sf in string_findings:
            by_type.setdefault(sf.string_type, []).append(sf)

        type_order = [
            StringType.NAMED_PIPE, StringType.SDDL, StringType.PRIVILEGE,
            StringType.REGISTRY_PATH, StringType.COMMAND, StringType.CLSID,
            StringType.UNC_PATH, StringType.FILE_PATH, StringType.URL,
            StringType.ENVIRONMENT_VAR, StringType.SERVICE_NAME,
        ]
        for st in type_order:
            if st not in by_type:
                continue
            items = by_type[st]
            label = st.value.replace("_", " ").upper()
            print(f"\n  {_magenta(label)}")
            for sf in items:
                loc = _dim(f"[{sf.section} +0x{sf.offset:x} {sf.encoding}]")
                print(f"    {_cyan(sf.value)}")
                print(f"      {loc}")
        print()
    else:
        print(_dim("No interesting strings found."))
        print()

    # IOCTL codes (drivers)
    if ioctl_codes:
        print(_bold(f"IOCTL CODES ({len(ioctl_codes)})"))
        for ic in ioctl_codes:
            method_color = _red if ic.method_name == "NEITHER" else (_yellow if ic.method_name != "BUFFERED" else _dim)
            print(f"  {_white(f'0x{ic.code:08X}')}  "
                  f"Device={_cyan(ic.device_type_name)}  "
                  f"Func=0x{ic.function:X}  "
                  f"Method={method_color(ic.method_name)}  "
                  f"Access={ic.access_name}")
            if ic.method_name == "NEITHER":
                print(f"    {_red('WARNING:')} METHOD_NEITHER — raw user pointers, high bug potential")
            elif ic.method_name in ("IN_DIRECT", "OUT_DIRECT"):
                print(f"    {_yellow('NOTE:')} Direct I/O — check MDL handling")
        print()

    # SDDL analysis
    if sddl_findings:
        print(_bold(f"SDDL ANALYSIS ({len(sddl_findings)})"))
        for sf in sddl_findings:
            sev_color = {"critical": _red, "high": _red, "medium": _yellow, "low": _cyan}.get(sf.severity, _dim)
            print(f"  {sev_color(sf.severity.upper())} at offset 0x{sf.offset:x}")
            truncated = sf.sddl_string[:80] + "..." if len(sf.sddl_string) > 80 else sf.sddl_string
            print(f"    {_dim(truncated)}")
            for issue in sf.issues:
                print(f"    {_yellow('>')} {issue}")
        print()

    # Export analysis
    if export_findings:
        print(_bold(f"EXPORT ANALYSIS ({len(export_findings)})"))
        for ef in export_findings:
            cat_color = _magenta if ef.category == "Binary Type" else _cyan
            print(f"  {cat_color(f'[{ef.category}]')} {_white(ef.name)}")
            print(f"    {_dim(ef.description)}")
            if ef.lpe_note:
                print(f"    {_yellow('LPE:')} {ef.lpe_note}")
        print()

    # Import-string cross-references
    if xref_findings:
        print(_bold(f"IMPORT-STRING CROSS-REFERENCES ({len(xref_findings)})"))
        by_cat = {}
        for xf in xref_findings:
            by_cat.setdefault(xf.api_category, []).append(xf)
        for cat, xrefs in by_cat.items():
            print(f"\n  {_magenta(cat.replace('_', ' ').upper())}")
            for xf in xrefs[:10]:
                print(f"    {_white(xf.api_name)} + {_cyan(xf.string_value[:70])}")
                print(f"      {_dim(xf.note)}")
            if len(xrefs) > 10:
                print(f"    {_dim(f'... and {len(xrefs)-10} more')}")
        print()

    # Ghidra deep analysis
    if ghidra_findings:
        if ghidra_findings.traced_calls:
            print(_bold(f"GHIDRA: TRACED API CALLS ({len(ghidra_findings.traced_calls)})"))
            for tc in ghidra_findings.traced_calls:
                args_str = ", ".join(tc.resolved_args[:3]) if tc.resolved_args else "unresolved"
                print(f"  {_white(tc.api)} in {_cyan(tc.caller)} @ {_dim(tc.address)}")
                print(f"    Args: {_yellow(args_str)}")
                if tc.risk_note:
                    print(f"    {_red('>')} {tc.risk_note}")
            print()

        if ghidra_findings.entry_paths:
            print(_bold(f"GHIDRA: ENTRY POINT TO API PATHS ({len(ghidra_findings.entry_paths)})"))
            for ep in ghidra_findings.entry_paths:
                path_str = " -> ".join(ep.path)
                print(f"  {_cyan(ep.entry_point)} -> {_red(ep.api)}")
                print(f"    {_dim(path_str)}")
            print()

        if ghidra_findings.insights:
            print(_bold(f"GHIDRA: DECOMPILED INSIGHTS ({len(ghidra_findings.insights)})"))
            for ins in ghidra_findings.insights:
                sev_color = {"critical": _red, "high": _red, "medium": _yellow}.get(ins.severity, _dim)
                print(f"  {sev_color(ins.severity.upper())} {_white(ins.function)} @ {_dim(ins.address)}")
                print(f"    {ins.detail}")
            print()

    # Summary
    ioctl_count = len(ioctl_codes) if ioctl_codes else 0
    sddl_count = len(sddl_findings) if sddl_findings else 0
    export_count = len(export_findings) if export_findings else 0
    total = len(import_findings) + len(hijack_candidates) + len(string_findings) + ioctl_count + sddl_count + export_count
    crit_high = sum(1 for f in import_findings if f.api.severity in (Severity.CRITICAL, Severity.HIGH))
    neither_count = sum(1 for ic in (ioctl_codes or []) if ic.method_name == "NEITHER")
    print(_bold("SUMMARY"))
    print(f"  Total findings:   {total}")
    print(f"  Critical/High:    {_red(str(crit_high)) if crit_high else _green('0')}")
    print(f"  Hijack candidates:{_red(str(len(hijack_candidates))) if hijack_candidates else _green('0')}")
    print(f"  Strings:          {len(string_findings)}")
    if ioctl_count:
        print(f"  IOCTL codes:      {ioctl_count}" + (f" ({_red(f'{neither_count} METHOD_NEITHER')})" if neither_count else ""))
    if sddl_count:
        sddl_crit = sum(1 for s in sddl_findings if s.severity in ("critical", "high"))
        print(f"  SDDL issues:      {sddl_count}" + (f" ({_red(f'{sddl_crit} critical/high')})" if sddl_crit else ""))
    if export_count:
        print(f"  Notable exports:  {export_count}")
    xref_count = len(xref_findings) if xref_findings else 0
    if xref_count:
        print(f"  Cross-references: {xref_count}")
    if ghidra_findings:
        g_total = len(ghidra_findings.traced_calls) + len(ghidra_findings.entry_paths) + len(ghidra_findings.insights)
        if g_total:
            print(f"  Ghidra findings:  {g_total} ({len(ghidra_findings.traced_calls)} traced, "
                  f"{len(ghidra_findings.entry_paths)} paths, {len(ghidra_findings.insights)} insights)")
    print()


def to_json(
    pe_info: PEInfo,
    metadata: MetadataFindings,
    import_findings: List[ImportFinding],
    string_findings: List[StringFinding],
    hijack_candidates: List[HijackCandidate],
    ioctl_codes: List[IoctlCode] = None,
    sddl_findings: List[SddlFinding] = None,
    export_findings: List[ExportFinding] = None,
    xref_findings: List[XrefFinding] = None,
    ghidra_findings: GhidraFindings = None,
) -> dict:
    return {
        "target": {
            "path": str(pe_info.path),
            "type": metadata.binary_type,
            "arch": metadata.arch,
            "subsystem": metadata.subsystem,
            "entry_point": metadata.entry_point,
            "image_base": metadata.image_base,
            "linker_version": metadata.linker_version,
        },
        "hardening": {
            "aslr": metadata.aslr,
            "high_entropy_aslr": metadata.high_entropy_aslr,
            "dep": metadata.dep,
            "cfg": metadata.cfg,
            "force_integrity": metadata.force_integrity,
            "seh_protection": not metadata.no_seh,
            "authenticode": metadata.signed,
        },
        "sections": pe_info.sections,
        "dangerous_imports": [
            {
                "api": f.api.name,
                "dll": f.dll,
                "category": f.api.category.value,
                "severity": f.api.severity.value,
                "description": f.api.description,
                "lpe_relevance": f.api.lpe_relevance,
            }
            for f in import_findings
        ],
        "hijack_candidates": [
            {
                "dll": h.dll_name,
                "reason": h.reason,
                "delay_loaded": h.is_delay_loaded,
                "imported_functions": h.imported_functions,
            }
            for h in hijack_candidates
        ],
        "strings": [
            {
                "value": sf.value,
                "type": sf.string_type.value,
                "offset": sf.offset,
                "section": sf.section,
                "encoding": sf.encoding,
            }
            for sf in string_findings
        ],
        "ioctl_codes": [
            {
                "code": f"0x{ic.code:08X}",
                "device_type": ic.device_type_name,
                "function": ic.function,
                "method": ic.method_name,
                "access": ic.access_name,
                "offset": ic.offset,
            }
            for ic in (ioctl_codes or [])
        ],
        "sddl_analysis": [
            {
                "sddl": sf.sddl_string,
                "offset": sf.offset,
                "severity": sf.severity,
                "issues": sf.issues,
            }
            for sf in (sddl_findings or [])
        ],
        "exports": [
            {
                "name": ef.name,
                "category": ef.category,
                "description": ef.description,
                "lpe_note": ef.lpe_note,
            }
            for ef in (export_findings or [])
        ],
        "cross_references": [
            {
                "api": xf.api_name,
                "category": xf.api_category,
                "string": xf.string_value,
                "string_type": xf.string_type,
                "note": xf.note,
            }
            for xf in (xref_findings or [])
        ],
        "ghidra": {
            "traced_calls": [
                {
                    "api": tc.api,
                    "caller": tc.caller,
                    "address": tc.address,
                    "resolved_args": tc.resolved_args,
                    "risk_note": tc.risk_note,
                }
                for tc in (ghidra_findings.traced_calls if ghidra_findings else [])
            ],
            "entry_paths": [
                {
                    "entry": ep.entry_point,
                    "api": ep.api,
                    "path": ep.path,
                }
                for ep in (ghidra_findings.entry_paths if ghidra_findings else [])
            ],
            "insights": [
                {
                    "function": ins.function,
                    "address": ins.address,
                    "pattern": ins.pattern,
                    "detail": ins.detail,
                    "severity": ins.severity,
                }
                for ins in (ghidra_findings.insights if ghidra_findings else [])
            ],
        } if ghidra_findings else None,
    }


def write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
