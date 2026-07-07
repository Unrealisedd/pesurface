"""SDDL / security descriptor analysis.

Parses SDDL strings found in PE binaries and flags weak permissions:
- NULL DACLs (Everyone full access)
- World-writable objects
- Anonymous access
- Low integrity
- Dangerous trustee SIDs
"""

import re
from dataclasses import dataclass
from typing import List
from .strings import StringFinding, StringType


WELL_KNOWN_SIDS = {
    "WD": "Everyone",
    "AN": "Anonymous",
    "AU": "Authenticated Users",
    "BU": "Built-in Users",
    "BA": "Built-in Administrators",
    "SY": "Local System",
    "CO": "Creator Owner",
    "BO": "Backup Operators",
    "PU": "Power Users",
    "SO": "Server Operators",
    "BG": "Built-in Guests",
    "RC": "Restricted Code",
    "AC": "All Application Packages",
    "LS": "Local Service",
    "NS": "Network Service",
    "IU": "Interactive Users",
    "NU": "Network Users",
    "ED": "Enterprise Domain Controllers",
    "RU": "Pre-W2K Compatible Access",
    "PS": "Self",
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-16-0": "Untrusted Integrity",
    "S-1-16-4096": "Low Integrity",
    "S-1-16-8192": "Medium Integrity",
    "S-1-16-8448": "Medium-Plus Integrity",
    "S-1-16-12288": "High Integrity",
    "S-1-16-16384": "System Integrity",
    "S-1-15-2-1": "All App Packages",
}

ACE_PATTERN = re.compile(r"\(([^)]+)\)")

FULL_ACCESS_MASKS = {"FA", "GA", "0x1F01FF", "0x1FFFFF", "0x10000000"}

DANGEROUS_TRUSTEES = {"WD", "AN", "BU", "BG", "AC", "S-1-1-0", "S-1-5-7", "IU"}


@dataclass
class SddlFinding:
    sddl_string: str
    offset: int
    issues: List[str]
    severity: str
    aces_parsed: List[dict]


def _parse_ace(ace_str: str) -> dict:
    parts = ace_str.split(";")
    result = {
        "raw": ace_str,
        "type": parts[0] if len(parts) > 0 else "",
        "flags": parts[1] if len(parts) > 1 else "",
        "rights": parts[2] if len(parts) > 2 else "",
        "object_guid": parts[3] if len(parts) > 3 else "",
        "inherit_guid": parts[4] if len(parts) > 4 else "",
        "trustee": parts[5] if len(parts) > 5 else "",
    }
    trustee = result["trustee"]
    result["trustee_name"] = WELL_KNOWN_SIDS.get(trustee, trustee)
    return result


def analyze_sddl(sddl: str, offset: int = 0) -> SddlFinding:
    issues = []
    aces = []

    if sddl.startswith("D:") and "()" in sddl:
        issues.append("Empty DACL — no access control (deny all)")

    if "D:" not in sddl and "O:" not in sddl and "S:" not in sddl:
        return SddlFinding(sddl, offset, ["Not a valid SDDL string"], "info", [])

    for m in ACE_PATTERN.finditer(sddl):
        ace_str = m.group(1)
        ace = _parse_ace(ace_str)
        aces.append(ace)

        trustee = ace["trustee"]
        rights = ace["rights"]
        ace_type = ace["type"]

        if ace_type == "A":
            if trustee in DANGEROUS_TRUSTEES:
                trustee_name = WELL_KNOWN_SIDS.get(trustee, trustee)
                if rights in FULL_ACCESS_MASKS or rights == "FA" or rights == "GA":
                    issues.append(f"CRITICAL: {trustee_name} ({trustee}) has FULL ACCESS")
                elif "WP" in rights or "WD" in rights or "WO" in rights:
                    issues.append(f"HIGH: {trustee_name} ({trustee}) has write permissions ({rights})")
                elif "CC" in rights or "DC" in rights:
                    issues.append(f"MEDIUM: {trustee_name} ({trustee}) can create/delete children ({rights})")
                else:
                    issues.append(f"INFO: {trustee_name} ({trustee}) allowed: {rights}")

    for m in re.finditer(r"S:\(ML;[^)]*;([^)]*);([^)]*)\)", sddl):
        rights = m.group(1)
        sid = m.group(2)
        label = WELL_KNOWN_SIDS.get(sid, sid)
        if "S-1-16-0" in sid or "S-1-16-4096" in sid:
            issues.append(f"HIGH: Mandatory label = {label} — low-privilege processes can access")

    if not issues:
        severity = "info"
    elif any("CRITICAL" in i for i in issues):
        severity = "critical"
    elif any("HIGH" in i for i in issues):
        severity = "high"
    elif any("MEDIUM" in i for i in issues):
        severity = "medium"
    else:
        severity = "low"

    return SddlFinding(sddl, offset, issues, severity, aces)


def analyze(string_findings: List[StringFinding]) -> List[SddlFinding]:
    results = []

    for sf in string_findings:
        if sf.string_type == StringType.SDDL:
            finding = analyze_sddl(sf.value, sf.offset)
            if finding.issues:
                results.append(finding)

    results.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 5))
    return results
