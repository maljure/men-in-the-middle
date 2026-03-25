"""
CA install helper — trust the MITM root CA in your OS / browser cert store.

Usage:
    python install_ca.py          # install
    python install_ca.py remove   # uninstall (where supported)

Requires admin/sudo on most platforms.
"""

import platform
import subprocess
import sys
from pathlib import Path

CA_CERT_PATH = Path("ca") / "ca.crt"
CA_NAME = "Men-in-the-Middle CA"


def _require_ca() -> None:
    if not CA_CERT_PATH.exists():
        print(f"[!] CA cert not found at {CA_CERT_PATH}")
        print("    Start the proxy once to generate it, then re-run this script.")
        sys.exit(1)


def install_windows() -> None:
    """Install into the Windows Root cert store (requires admin)."""
    cert = str(CA_CERT_PATH.resolve())
    result = subprocess.run(
        ["certutil", "-addstore", "-f", "Root", cert],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
        print("[!] certutil failed — are you running as Administrator?")
        sys.exit(result.returncode)
    print("[+] CA installed in Windows Root store.")
    print("    Chrome and Edge will trust it immediately.")
    print("    Firefox uses its own store — see the Firefox note below.")


def remove_windows() -> None:
    result = subprocess.run(
        ["certutil", "-delstore", "Root", CA_NAME],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    else:
        print("[+] CA removed from Windows Root store.")


def install_macos() -> None:
    """Install into the macOS System keychain (requires sudo)."""
    cert = str(CA_CERT_PATH.resolve())
    result = subprocess.run(
        [
            "sudo", "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            cert,
        ],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
        print("[!] security command failed.")
        sys.exit(result.returncode)
    print("[+] CA installed in macOS System keychain.")


def remove_macos() -> None:
    result = subprocess.run(
        [
            "sudo", "security", "delete-certificate",
            "-c", CA_NAME,
            "/Library/Keychains/System.keychain",
        ],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    else:
        print("[+] CA removed from macOS System keychain.")


def install_linux() -> None:
    """
    Install into the system CA bundle.
    Supports Debian/Ubuntu (update-ca-certificates) and RHEL/Fedora (update-ca-trust).
    """
    import shutil

    cert_src = CA_CERT_PATH.resolve()

    # Debian / Ubuntu
    if Path("/usr/local/share/ca-certificates").exists():
        dest = Path("/usr/local/share/ca-certificates") / "mitm-ca.crt"
        shutil.copy(cert_src, dest)
        result = subprocess.run(["sudo", "update-ca-certificates"], capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode == 0:
            print("[+] CA installed (Debian/Ubuntu).")
        else:
            sys.exit(result.returncode)

    # RHEL / Fedora / CentOS
    elif Path("/etc/pki/ca-trust/source/anchors").exists():
        dest = Path("/etc/pki/ca-trust/source/anchors") / "mitm-ca.crt"
        subprocess.run(["sudo", "cp", str(cert_src), str(dest)], check=True)
        result = subprocess.run(["sudo", "update-ca-trust", "extract"], capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode == 0:
            print("[+] CA installed (RHEL/Fedora).")
        else:
            sys.exit(result.returncode)
    else:
        print("[!] Unknown Linux distribution — install manually:")
        print(f"    Copy {cert_src} to your system CA bundle directory")
        print("    and run the appropriate update command.")
        sys.exit(1)


def print_firefox_note() -> None:
    print()
    print("Firefox note:")
    print("  Firefox manages its own cert store. To trust this CA in Firefox:")
    print("  Settings → Privacy & Security → Certificates → View Certificates")
    print("  → Authorities → Import → select ca/ca.crt")
    print("  Check 'Trust this CA to identify websites' and click OK.")


def main() -> None:
    _require_ca()
    removing = len(sys.argv) > 1 and sys.argv[1] == "remove"
    system = platform.system()

    if system == "Windows":
        remove_windows() if removing else install_windows()
    elif system == "Darwin":
        remove_macos() if removing else install_macos()
    elif system == "Linux":
        if removing:
            print("[!] Automatic removal not implemented for Linux — delete manually.")
        else:
            install_linux()
    else:
        print(f"[!] Unsupported platform: {system}")
        sys.exit(1)

    if not removing:
        print_firefox_note()


if __name__ == "__main__":
    main()
