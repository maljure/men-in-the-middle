import dataclasses
import re
from typing import List
import time

import http_parser
import fuzzer


@dataclasses.dataclass
class ScanFinding:
    """A structured finding from any of the scanner modules."""
    scanner: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH"
    title: str
    description: str
    evidence: str = ""

# ==========================================
# 1. Header Analysis Scanner
# ==========================================

def scan_headers(resp: http_parser.HTTPResponse) -> List[ScanFinding]:
    """Analyzes response headers for missing security controls."""
    findings = []
    
    # HTTPResponse.headers already has lower-cased keys for easy lookup
    headers = resp.headers

    # Check HSTS (Strict-Transport-Security)
    if "strict-transport-security" not in headers:
        findings.append(ScanFinding(
            scanner="Header Analysis",
            severity="LOW",
            title="Missing HSTS Header",
            description="The response is missing the Strict-Transport-Security header, leaving the user vulnerable to MITM downgrade attacks.",
        ))

    # Check CSP (Content-Security-Policy)
    if "content-security-policy" not in headers:
        findings.append(ScanFinding(
            scanner="Header Analysis",
            severity="INFO",
            title="Missing Content-Security-Policy",
            description="No CSP is defined, making it easier for attackers to execute Cross-Site Scripting (XSS) attacks.",
        ))

    # Check Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
    has_xfo = "x-frame-options" in headers
    has_csp_frame = "frame-ancestors" in headers.get("content-security-policy", "")
    if not (has_xfo or has_csp_frame):
        findings.append(ScanFinding(
            scanner="Header Analysis",
            severity="LOW",
            title="Missing Clickjacking Protection",
            description="Neither X-Frame-Options nor CSP frame-ancestors are present. The site can be embedded in an iframe.",
        ))

    # Check MIME Sniffing protection
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(ScanFinding(
            scanner="Header Analysis",
            severity="LOW",
            title="Missing X-Content-Type-Options",
            description="The X-Content-Type-Options header is missing or not set to 'nosniff'.",
            evidence=f"Current value: {headers.get('x-content-type-options', 'None')}"
        ))

    return findings


# ==========================================
# 2. Sensitive Data Scanner
# ==========================================

# Pre-compile regexes for performance
SENSITIVE_REGEXES = {
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Bearer Token": re.compile(r"Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)"),
    "Email Address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "Social Security Number": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Basic Auth Credentials": re.compile(r"Basic\s+([A-Za-z0-9+/=]+)"),
}

def scan_sensitive_data(resp: http_parser.HTTPResponse) -> List[ScanFinding]:
    """Scans the response body and headers for exposed secrets and PII."""
    findings = []
    
    # 1. Scan the Response Body
    if resp.body:
        body_text = resp.body.decode("utf-8", errors="ignore")
        for pattern_name, regex in SENSITIVE_REGEXES.items():
            matches = set(regex.findall(body_text)) # Use set to deduplicate
            for match in matches:
                # If the regex uses groups (like Bearer Token), match is just the group.
                # If it doesn't (like AWS key), match is the whole string.
                evidence = match if isinstance(match, str) else str(match)
                
                # Keep severity high for tokens, medium for PII
                severity = "HIGH" if "Token" in pattern_name or "Key" in pattern_name or "Auth" in pattern_name else "MEDIUM"
                
                findings.append(ScanFinding(
                    scanner="Sensitive Data",
                    severity=severity,
                    title=f"Exposed {pattern_name} in Body",
                    description=f"Found a potential {pattern_name} exposed in the response body.",
                    evidence=f"...{evidence}..."
                ))

    # 2. Scan the Headers (Sometimes APIs leak tokens in custom response headers)
    for name, value in resp.raw_headers:
        for pattern_name, regex in SENSITIVE_REGEXES.items():
            matches = set(regex.findall(value))
            for match in matches:
                evidence = match if isinstance(match, str) else str(match)
                findings.append(ScanFinding(
                    scanner="Sensitive Data",
                    severity="HIGH",
                    title=f"Exposed {pattern_name} in Header",
                    description=f"Found a potential {pattern_name} exposed in the '{name}' response header.",
                    evidence=f"{name}: {evidence}"
                ))

    return findings


# ==========================================
# 3. Directory Scanner
# ==========================================

DEFAULT_DIRECTORIES = [
    ".git/config",
    ".env",
    "admin/",
    "api/v1/users",
    "backup.zip",
    "server-status",
    "phpinfo.php",
    "robots.txt"
]

def scan_directories(host: str, port: int, protocol: str, wordlist: List[str] | None = None) -> List[ScanFinding]:
    """Fuzzes common paths against the target to find hidden directories."""
    findings = []
    paths_to_check = wordlist if wordlist else DEFAULT_DIRECTORIES

    print(f"[*] Starting Directory Scan on {protocol}://{host}:{port}")
    print(f"[*] Testing {len(paths_to_check)} paths...")

    for path in paths_to_check:
        time.sleep(0.2)
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path

        # Construct a raw GET request
        req = http_parser.HTTPRequest(
            method="GET",
            path=path,
            version="HTTP/1.1",
            headers={"host": host, "user-agent": "MITM-Scanner/1.0", "accept": "*/*"},
            raw_headers=[("Host", host), ("User-Agent", "MITM-Scanner/1.0"), ("Accept", "*/*")],
            body=b""
        )

        try:
            # We reuse your fuzzer's sendRequest method!
            resp, elapsed = fuzzer.sendRequest(req, host, port, protocol)
            
            # 200 OK means we found it. 403 Forbidden means it exists but we lack permissions.
            if resp.status_code == 200:
                findings.append(ScanFinding(
                    scanner="Directory Scanner",
                    severity="MEDIUM",
                    title="Hidden File/Directory Found",
                    description=f"A potentially sensitive file or directory is publicly accessible.",
                    evidence=f"GET {path} -> 200 OK ({len(resp.body)} bytes)"
                ))
            elif resp.status_code == 403:
                findings.append(ScanFinding(
                    scanner="Directory Scanner",
                    severity="INFO",
                    title="Forbidden Directory Found",
                    description=f"A directory exists but access is forbidden.",
                    evidence=f"GET {path} -> 403 Forbidden"
                ))
                
        except Exception as e:
            # Drop silent on network failures for individual fuzz requests
            pass

    return findings


# ==========================================
# 4. Reporting / CLI Printing
# ==========================================

def print_findings(findings: List[ScanFinding]) -> None:
    """Consumes ScanFindings and prints them beautifully for the CLI."""
    if not findings:
        print("\n[+] No vulnerabilities found during scan.")
        return

    print(f"\n{'='*80}")
    print(f"  SCAN RESULTS — {len(findings)} findings")
    print(f"{'='*80}")

    # Sort by severity so HIGH shows up first
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 4))

    for i, finding in enumerate(sorted_findings, 1):
        # Add basic terminal colors if supported, otherwise just text
        sev_tag = f"[{finding.severity}]"
        
        print(f"\n{i}. {sev_tag} {finding.title} ({finding.scanner})")
        print(f"   Description : {finding.description}")
        if finding.evidence:
            print(f"   Evidence    : {finding.evidence}")

    print(f"\n{'='*80}\n")