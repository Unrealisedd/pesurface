"""Ghidra headless runner — invokes analyzeHeadless and collects results."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional


GHIDRA_PATHS = [
    os.environ.get("GHIDRA_HOME", ""),
    os.path.expanduser("~/ghidra"),
    r"C:\Users\vanmo\Downloads\ghidra_12.0.4_PUBLIC",
    r"C:\ghidra",
    r"C:\Program Files\Ghidra",
    r"C:\Program Files (x86)\Ghidra",
    "/opt/ghidra",
    "/usr/local/ghidra",
    os.path.expanduser("~/ghidra_*"),
]

SCRIPT_DIR = Path(__file__).parent


@dataclass
class ApiCallTrace:
    api: str
    caller: str
    address: str
    resolved_args: List[str] = field(default_factory=list)


@dataclass
class CallGraphEntry:
    entry: str
    address: str
    tree: list = field(default_factory=list)


@dataclass
class FunctionSummary:
    name: str
    address: str
    size: int
    decompiled: Optional[str] = None


@dataclass
class GhidraResults:
    program: str
    language: str
    api_calls: List[ApiCallTrace] = field(default_factory=list)
    call_graphs: List[CallGraphEntry] = field(default_factory=list)
    functions: List[FunctionSummary] = field(default_factory=list)


def find_ghidra() -> Optional[str]:
    """Find analyzeHeadless on the system."""
    import glob

    for base in GHIDRA_PATHS:
        if not base:
            continue
        for pattern in [base, base + "*"]:
            for d in glob.glob(pattern):
                bat = os.path.join(d, "support", "analyzeHeadless.bat")
                sh = os.path.join(d, "support", "analyzeHeadless")
                if os.path.isfile(bat):
                    return bat
                if os.path.isfile(sh):
                    return sh
    return None


def run_headless(target_path: str, ghidra_path: str = None, timeout: int = 300) -> Optional[GhidraResults]:
    """Run Ghidra headless analysis on a PE binary.

    Args:
        target_path: Path to the PE file to analyze
        ghidra_path: Path to analyzeHeadless (auto-detected if None)
        timeout: Max seconds to wait for Ghidra (default 5 min)

    Returns:
        GhidraResults or None if Ghidra fails/not found
    """
    if ghidra_path is None:
        ghidra_path = find_ghidra()

    if ghidra_path is None:
        return None

    target = Path(target_path).resolve()
    if not target.exists():
        return None

    # Create temp directory for Ghidra project and output
    tmpdir = tempfile.mkdtemp(prefix="pesurface_ghidra_")
    project_dir = os.path.join(tmpdir, "project")
    os.makedirs(project_dir, exist_ok=True)
    output_json = os.path.join(tmpdir, "results.json")
    script_path = "PesurfaceAnalyze.java"

    project_name = "pesurface_tmp"

    cmd = [
        ghidra_path,
        project_dir,
        project_name,
        "-import", str(target),
        "-postScript", script_path, output_json,
        "-scriptPath", str(SCRIPT_DIR),
        "-deleteProject",
    ]

    # On Windows, run through cmd to handle .bat
    if sys.platform == "win32" and ghidra_path.endswith(".bat"):
        cmd = ["cmd", "/c"] + cmd

    print(f"  Running Ghidra headless analysis (timeout={timeout}s)...")
    print(f"  Target: {target}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=tmpdir,
        )
    except subprocess.TimeoutExpired:
        print(f"  Ghidra timed out after {timeout}s")
        _cleanup(tmpdir)
        return None
    except FileNotFoundError:
        print(f"  Ghidra not found at: {ghidra_path}")
        _cleanup(tmpdir)
        return None

    # Show relevant Ghidra output
    if result.stdout:
        for line in result.stdout.splitlines():
            if "[pesurface]" in line or "ERROR" in line or "SCRIPT ERROR" in line:
                print(f"  {line.strip()}")

    if result.returncode != 0:
        if not os.path.isfile(output_json):
            stderr_tail = result.stderr[-500:] if result.stderr else "no stderr"
            stdout_tail = result.stdout[-500:] if result.stdout else ""
            print(f"  Ghidra failed (exit {result.returncode})")
            if "ERROR" in stdout_tail:
                print(f"  {stdout_tail}")
            _cleanup(tmpdir)
            return None

    if not os.path.isfile(output_json):
        print("  Ghidra produced no output file")
        _cleanup(tmpdir)
        return None

    try:
        with open(output_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  Failed to parse Ghidra output: {e}")
        _cleanup(tmpdir)
        return None

    _cleanup(tmpdir)
    return _parse_results(data)


def _parse_results(data: dict) -> GhidraResults:
    results = GhidraResults(
        program=data.get("program", "unknown"),
        language=data.get("language", "unknown"),
    )

    for ac in data.get("api_calls", []):
        results.api_calls.append(ApiCallTrace(
            api=ac.get("api", ""),
            caller=ac.get("caller", ""),
            address=ac.get("address", ""),
            resolved_args=ac.get("resolved_args", []),
        ))

    for cg in data.get("call_graphs", []):
        results.call_graphs.append(CallGraphEntry(
            entry=cg.get("entry", ""),
            address=cg.get("address", ""),
            tree=cg.get("tree", []),
        ))

    for fn in data.get("functions", []):
        results.functions.append(FunctionSummary(
            name=fn.get("name", ""),
            address=fn.get("address", ""),
            size=fn.get("size", 0),
            decompiled=fn.get("decompiled"),
        ))

    return results


def load_cached(json_path: str) -> Optional[GhidraResults]:
    """Load previously saved Ghidra results from JSON."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return _parse_results(data)
    except (json.JSONDecodeError, IOError, KeyError):
        return None


def _cleanup(tmpdir: str):
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass
