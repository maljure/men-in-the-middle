"""TLS interception layer — CA management and dynamic cert factory."""

import datetime
import ipaddress
import logging
import os
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger(__name__)

# Paths and constants
CA_DIR = Path("ca")
CA_CERT_PATH = CA_DIR / "ca.crt"
CA_KEY_PATH = CA_DIR / "ca.key"

CA_VALIDITY_DAYS = 825
HOST_CERT_VALIDITY_DAYS = 395 

# Cert cache
_cert_cache: dict[str, tuple[bytes, bytes]] = {}
_cert_cache_lock = threading.Lock()


def get_cached_cert(hostname: str) -> tuple[bytes, bytes] | None:
    """Return cached (cert_pem, key_pem) for hostname, or None."""
    with _cert_cache_lock:
        return _cert_cache.get(hostname)


def store_cert(hostname: str, cert_pem: bytes, key_pem: bytes) -> None:
    """Cache (cert_pem, key_pem) for hostname."""
    with _cert_cache_lock:
        _cert_cache[hostname] = (cert_pem, key_pem)



# Key generation
def _new_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _key_to_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )



# Root CA - generate or load from disk
def generate_ca() -> tuple:
    """
    Generate a new root CA cert and key, persist to CA_DIR, and return
    (cert, key) as cryptography objects.
    """
    CA_DIR.mkdir(parents=True, exist_ok=True)
    key = _new_rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Men-in-the-Middle CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MITM Proxy"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(_key_to_pem(key))
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("Generated new root CA → %s", CA_CERT_PATH.resolve())
    return cert, key


def load_or_create_ca() -> tuple:
    """
    Load root CA from disk if both files exist, otherwise generate a fresh one.
    Returns (cert, key) as cryptography objects.
    """
    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        cert = load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        key = load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        log.info("Loaded CA from disk: %s", CA_CERT_PATH.resolve())
        return cert, key
    return generate_ca()


# Per-hostname cert generation
def generate_host_cert(hostname: str, ca_cert, ca_key) -> tuple[bytes, bytes]:
    """
    Generate a leaf TLS cert for hostname signed by ca_cert / ca_key.
    Returns (cert_pem, key_pem).
    """
    key = _new_rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    try:
        san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=HOST_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = _key_to_pem(key)
    return cert_pem, key_pem


# SSL helpers
def get_host_ssl_context(hostname: str, ca_cert, ca_key) -> ssl.SSLContext:
    """
    Return a server-side SSLContext for hostname, backed by a cert signed by
    our CA. Generates and caches the cert on first call per hostname.
    """
    cached = get_cached_cert(hostname)
    if cached:
        cert_pem, key_pem = cached
    else:
        cert_pem, key_pem = generate_host_cert(hostname, ca_cert, ca_key)
        store_cert(hostname, cert_pem, key_pem)
        log.debug("Generated leaf cert for %s", hostname)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cf:
        cf.write(cert_pem)
        cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as kf:
        kf.write(key_pem)
        key_path = kf.name
    try:
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)

    return ctx


def make_upstream_context(verify: bool = True) -> ssl.SSLContext:
    """
    Create a client-side SSLContext for connecting to upstream servers.
    verify=True (default) — validates the server's certificate chain.
    verify=False — disables verification (useful for internal test servers).
    """
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
