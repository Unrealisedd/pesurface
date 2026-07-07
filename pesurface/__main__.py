"""pesurface CLI entry point — python -m pesurface"""

import argparse
import sys
import os

from . import __version__
from .loader import load
from .analyzers import imports, strings, dllhijack, metadata, ioctl, sddl, exports
from .analyzers import xref
from .analyzers.ghidra_analysis import analyze as ghidra_analyze, GhidraFindings
from .ghidra.runner import find_ghidra, run_headless, load_cached
from .report import print_report, to_json, write_json


def main():
    parser = argparse.ArgumentParser(
        prog="pesurface",
        description="PE Attack Surface Mapper — find LPE primitives in Windows binaries",
    )
    parser.add_argument("target", nargs="?", help="PE file to analyze (.exe, .dll, .sys)")
    parser.add_argument("--json", dest="json_out", metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only show findings, skip metadata")
    parser.add_argument("--version", "-V", action="version", version=f"pesurface {__version__}")
    parser.add_argument("--ghidra", action="store_true",
                        help="Run Ghidra headless analysis for deeper argument tracing and call graphs")
    parser.add_argument("--ghidra-path", metavar="PATH",
                        help="Path to analyzeHeadless (auto-detected if not set)")
    parser.add_argument("--ghidra-json", metavar="FILE",
                        help="Load previously saved Ghidra results instead of running headless")
    parser.add_argument("--ghidra-timeout", type=int, default=300,
                        help="Ghidra analysis timeout in seconds (default: 300)")

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    if args.no_color:
        from . import report as _r
        _r._COLOR = False

    if sys.platform == "win32":
        os.system("")

    target = args.target

    if not os.path.isfile(target):
        print(f"Error: {target} not found or not a file", file=sys.stderr)
        sys.exit(1)

    try:
        pe_info = load(target)
    except Exception as e:
        print(f"Error loading PE: {e}", file=sys.stderr)
        sys.exit(1)

    # Core analyzers
    meta = metadata.analyze(pe_info)
    import_findings = imports.analyze(pe_info)
    string_findings = strings.analyze(pe_info)
    hijack_candidates = dllhijack.analyze(pe_info)
    ioctl_codes = ioctl.analyze(pe_info)
    sddl_findings = sddl.analyze(string_findings)
    export_findings = exports.analyze(pe_info)
    xref_findings = xref.analyze(import_findings, string_findings)

    # Ghidra deep analysis
    ghidra_findings = None
    if args.ghidra_json:
        gr = load_cached(args.ghidra_json)
        if gr:
            ghidra_findings = ghidra_analyze(gr)
            print(f"Loaded Ghidra results from {args.ghidra_json}")
        else:
            print(f"Warning: could not load {args.ghidra_json}", file=sys.stderr)
    elif args.ghidra:
        ghidra_path = args.ghidra_path or find_ghidra()
        if ghidra_path:
            gr = run_headless(target, ghidra_path, timeout=args.ghidra_timeout)
            if gr:
                ghidra_findings = ghidra_analyze(gr)
            else:
                print("Warning: Ghidra analysis produced no results", file=sys.stderr)
        else:
            print("Error: Ghidra not found. Set --ghidra-path or GHIDRA_HOME env var.",
                  file=sys.stderr)

    if not args.quiet:
        print_report(pe_info, meta, import_findings, string_findings, hijack_candidates,
                     ioctl_codes, sddl_findings, export_findings, xref_findings, ghidra_findings)
    else:
        total = (len(import_findings) + len(hijack_candidates) + len(string_findings)
                 + len(ioctl_codes) + len(sddl_findings) + len(export_findings)
                 + len(xref_findings))
        ghidra_str = ""
        if ghidra_findings:
            g = len(ghidra_findings.traced_calls) + len(ghidra_findings.entry_paths) + len(ghidra_findings.insights)
            ghidra_str = f", {g} ghidra"
            total += g
        print(f"{target}: {total} findings ({len(import_findings)} imports, "
              f"{len(hijack_candidates)} hijack, {len(string_findings)} strings, "
              f"{len(xref_findings)} xref{ghidra_str})")

    if args.json_out:
        data = to_json(pe_info, meta, import_findings, string_findings, hijack_candidates,
                       ioctl_codes, sddl_findings, export_findings, xref_findings, ghidra_findings)
        write_json(args.json_out, data)
        print(f"\nJSON report written to {args.json_out}")


if __name__ == "__main__":
    main()
