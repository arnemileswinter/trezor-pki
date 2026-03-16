#!/usr/bin/env python3
"""
trezor-pki: Certificate Authority and JWT signing backed by Trezor hardware wallet.

Uses the SignIdentity (SLIP-0013) firmware feature with gpg:// URIs to get
raw ECDSA/Ed25519 signatures from the Trezor — no cryptocurrency framing.

Supports:
  - Deriving a CA keypair from Trezor seed + URI
  - Creating self-signed CA certificates
  - Signing CSRs to issue service certificates
  - Signing JWTs (ES256 / EdDSA)
  - Exporting the public key for JWT verification

Requires: pip install trezor cryptography

Curve support:
  - nist256p1 (P-256)  → ES256 JWTs, ECDSA X.509 certs (widest TLS compat)
  - secp256k1 (K-256)  → ES256K JWTs, ECDSA X.509 certs (Bitcoin curve)
  - ed25519            → EdDSA JWTs, Ed25519 X.509 certs
"""

import argparse
import base64
import hashlib
import json
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from trezorlib import exceptions, misc, messages, ui
    from trezorlib.client import get_client as _trezor_get_client, AppManifest
    from trezorlib.transport import get_transport
except ImportError:
    print("Error: trezorlib not installed. Run: pip install trezor", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.x509 import (
        CertificateBuilder, CertificateSigningRequestBuilder,
        BasicConstraints, SubjectAlternativeName, DNSName, IPAddress,
    )
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography not installed. Run: pip install cryptography", file=sys.stderr)
    sys.exit(1)

import ipaddress


# ---------------------------------------------------------------------------
# Trezor interaction helpers
# ---------------------------------------------------------------------------

def get_trezor_session():
    """Connect to the first available Trezor device and return a session."""
    transport = get_transport()
    click_ui = ui.ClickUI()
    manifest = AppManifest(
        app_name="trezor-pki",
        button_callback=click_ui.button_request,
        pin_callback=click_ui.get_pin,
    )
    client = _trezor_get_client(manifest, transport)
    session = client.get_session()
    return session


def make_identity(uri: str) -> messages.IdentityType:
    """
    Parse a gpg:// URI into a Trezor IdentityType.
    Format: gpg://user@host:port
    """
    if not uri.startswith("gpg://"):
        raise ValueError("URI must start with gpg://")

    rest = uri[6:]  # strip gpg://
    user = ""
    host = rest
    port = ""

    if "@" in rest:
        user, host = rest.rsplit("@", 1)
    if ":" in host:
        host, port = host.rsplit(":", 1)

    return messages.IdentityType(
        proto="gpg",
        user=user,
        host=host,
        port=port,
        index=0,
    )


def _curve_candidates(curve: str) -> list[str]:
    """Return firmware curve-name candidates in preferred order."""
    if curve == "nist256p1":
        # Some firmware/tooling paths use secp256r1 for the same curve.
        return ["nist256p1", "secp256r1"]
    return [curve]


def _sign_identity_with_curve_fallback(session, identity, challenge_hidden: bytes, curve: str):
    """Call SignIdentity with curve alias fallback for nist256p1 firmware quirks."""
    last_error = None
    for curve_name in _curve_candidates(curve):
        try:
            return misc.sign_identity(
                session,
                identity=identity,
                challenge_hidden=challenge_hidden,
                challenge_visual="",
                ecdsa_curve_name=curve_name,
            )
        except exceptions.TrezorFailure as err:
            last_error = err
            # Try next alias only for firmware-level failure.
            if "FirmwareError" not in str(err):
                raise

    # We exhausted aliases. Give an actionable error message.
    if curve == "nist256p1":
        raise RuntimeError(
            "Trezor firmware rejected nist256p1 SignIdentity on this device/firmware. "
            "Tried curve names: nist256p1, secp256r1. "
            "Please upgrade firmware or use --curve ed25519."
        ) from last_error
    raise last_error


def trezor_sign(session, uri: str, data: bytes, curve: str = "ed25519") -> tuple:
    """
    Sign arbitrary data using Trezor's SignIdentity.

    For gpg:// sigtype, the firmware passes challenge_hidden directly to the
    signing function without additional hashing. For ed25519, the firmware
    passes raw bytes to ed25519.sign() which does its own internal hashing.

    Returns (public_key_bytes, signature_bytes).
    """
    identity = make_identity(uri)

    # For gpg sigtype: data = challenge_hidden (passed directly to sign function)
    # Ed25519 hashes internally, so we pass raw data.
    # For nist256p1, the firmware expects a 32-byte SHA-256 hash as input.
    if curve in ("nist256p1", "secp256k1"):
        challenge = hashlib.sha256(data).digest()
    else:
        challenge = data

    result = _sign_identity_with_curve_fallback(session, identity, challenge, curve)

    # Result signature format:
    # - ed25519: b'\x00' + 64-byte signature
    # - nist256p1/secp256k1 with gpg sigtype: b'\x00' + 64-byte raw (r||s)
    pubkey = result.public_key
    signature = result.signature

    return pubkey, signature


def get_public_key(session, uri: str, curve: str = "ed25519") -> bytes:
    """Get the public key for a given identity URI without signing anything meaningful."""
    identity = make_identity(uri)
    # Sign a deterministic dummy challenge just to get the public key.
    # Safe 3 firmware rejects an all-zero challenge for nist256p1.
    dummy = hashlib.sha256(f"trezor-pki:get-public-key:{uri}".encode("utf-8")).digest()
    result = _sign_identity_with_curve_fallback(session, identity, dummy, curve)
    return result.public_key


# ---------------------------------------------------------------------------
# X.509 Certificate helpers
# ---------------------------------------------------------------------------

def pubkey_to_crypto_key(pubkey_bytes: bytes, curve: str):
    """
    Convert Trezor public key bytes to a cryptography library public key object.

    Trezor returns:
    - nist256p1: 33 bytes (compressed) or 65 bytes (uncompressed) SEC1
    - ed25519: 33 bytes (0x00 prefix + 32 byte key)
    """
    if curve == "nist256p1":
        # Trezor returns compressed SEC1 format (33 bytes, starting with 02 or 03)
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey_bytes)
    elif curve == "secp256k1":
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey_bytes)
    elif curve == "ed25519":
        # Strip 0x00 prefix
        raw_key = pubkey_bytes[1:] if pubkey_bytes[0] == 0 else pubkey_bytes
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
    else:
        raise ValueError(f"Unsupported curve: {curve}")


def trezor_signature_to_der(sig_bytes: bytes, curve: str) -> bytes:
    """
    Convert Trezor signature format to what cryptography lib expects.

    Trezor returns b'\x00' + r(32) + s(32) for ECDSA.
    X.509 needs DER-encoded ECDSA signature.
    For Ed25519, signature is raw 64 bytes (after stripping prefix).
    """
    if curve in ("nist256p1", "secp256k1"):
        # Strip leading 0x00, then encode r||s as DER
        raw = sig_bytes[1:]
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:64], "big")
        return utils.encode_dss_signature(r, s)
    elif curve == "ed25519":
        # Strip 0x00 prefix
        return sig_bytes[1:]
    else:
        raise ValueError(f"Unsupported curve: {curve}")


def build_ca_cert(session, uri: str, common_name: str, curve: str = "ed25519",
                  days: int = 3650) -> bytes:
    """
    Build a self-signed CA certificate using the Trezor.

    1. Get public key from Trezor
    2. Build the TBS (to-be-signed) certificate
    3. Sign the TBS with Trezor
    4. Assemble the final certificate

    Since we can't hook into cryptography's signing flow directly (it wants
    a private key object), we build the TBS manually, sign it externally,
    and assemble the cert.
    """
    pubkey = get_public_key(session, uri, curve)
    crypto_pubkey = pubkey_to_crypto_key(pubkey, curve)

    # We need to build the cert, sign TBS externally, and reassemble.
    # The cryptography library doesn't support external signing directly,
    # so we use a workaround: create a dummy-signed cert to get the TBS bytes,
    # then re-sign with Trezor.
    #
    # Alternative: use the lower-level asn1crypto or pyasn1 to build TBS manually.
    # For simplicity, we'll use a known working approach.

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)

    # Build TBS structure
    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(crypto_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(crypto_pubkey),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )

    # We need to sign externally, so we build TBS via a dummy-signed cert,
    # extract TBS, re-sign with Trezor, and rebuild the cert DER.

    tbs_bytes = _get_tbs_bytes(builder, curve)

    # Sign TBS with Trezor
    _, sig = trezor_sign(session, uri, tbs_bytes, curve)
    der_sig = trezor_signature_to_der(sig, curve)

    # Assemble final certificate DER
    cert_der = _assemble_cert_der(tbs_bytes, der_sig, curve)

    # Parse back to verify
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_bytes(serialization.Encoding.PEM)


def _get_tbs_bytes(builder, curve: str) -> bytes:
    """
    Extract TBS (to-be-signed) bytes from a CertificateBuilder.

    We create a throwaway cert with a dummy key, then extract the TBS portion.
    """
    if curve == "nist256p1":
        dummy_key = ec.generate_private_key(ec.SECP256R1())
        dummy_cert = builder.sign(dummy_key, hashes.SHA256())
    elif curve == "secp256k1":
        dummy_key = ec.generate_private_key(ec.SECP256K1())
        dummy_cert = builder.sign(dummy_key, hashes.SHA256())
    elif curve == "ed25519":
        dummy_key = ed25519.Ed25519PrivateKey.generate()
        dummy_cert = builder.sign(dummy_key, None)

    # The TBS is the first element of the certificate SEQUENCE
    cert_der = dummy_cert.public_bytes(serialization.Encoding.DER)
    return _extract_tbs_from_cert_der(cert_der)


def _extract_tbs_from_cert_der(cert_der: bytes) -> bytes:
    """Extract the TBS portion from a DER-encoded certificate."""
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    # TBS is the first element in the outer SEQUENCE
    # We parse just enough ASN.1 to extract it

    def parse_tag_length(data, offset):
        tag = data[offset]
        offset += 1
        length = data[offset]
        offset += 1
        if length & 0x80:
            num_bytes = length & 0x7F
            length = int.from_bytes(data[offset:offset + num_bytes], "big")
            offset += num_bytes
        return tag, length, offset

    # Outer SEQUENCE
    _, _, outer_content_start = parse_tag_length(cert_der, 0)

    # TBS SEQUENCE (first element)
    tbs_tag_offset = outer_content_start
    tag, length, content_start = parse_tag_length(cert_der, tbs_tag_offset)

    # TBS bytes = from tag start to end of content
    tbs_end = content_start + length
    return cert_der[tbs_tag_offset:tbs_end]


def _assemble_cert_der(tbs_bytes: bytes, signature: bytes, curve: str) -> bytes:
    """
    Assemble a DER-encoded X.509 certificate from TBS, algorithm ID, and signature.

    Certificate ::= SEQUENCE {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING
    }
    """

    def encode_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82]) + length.to_bytes(2, "big")
        else:
            return bytes([0x83]) + length.to_bytes(3, "big")

    def encode_sequence(contents: bytes) -> bytes:
        return bytes([0x30]) + encode_length(len(contents)) + contents

    def encode_bitstring(data: bytes) -> bytes:
        # BIT STRING with 0 unused bits
        content = bytes([0x00]) + data
        return bytes([0x03]) + encode_length(len(content)) + content

    def encode_oid(oid_bytes: bytes) -> bytes:
        return bytes([0x06]) + encode_length(len(oid_bytes)) + oid_bytes

    # Algorithm identifiers
    if curve in ("nist256p1", "secp256k1"):
        # ecdsa-with-SHA256: 1.2.840.10045.4.3.2
        # (curve is encoded in the SubjectPublicKeyInfo, not the sig alg OID)
        oid = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
        sig_alg = encode_sequence(encode_oid(oid))
    elif curve == "ed25519":
        # Ed25519: 1.3.101.112
        oid = bytes([0x2B, 0x65, 0x70])
        sig_alg = encode_sequence(encode_oid(oid))

    sig_bitstring = encode_bitstring(signature)

    cert_content = tbs_bytes + sig_alg + sig_bitstring
    return encode_sequence(cert_content)


def sign_csr(session, uri: str, ca_cert_pem: bytes, csr_pem: bytes,
             curve: str = "ed25519", days: int = 365) -> bytes:
    """
    Sign a CSR using the Trezor-backed CA key.

    1. Parse the CSR to get subject and public key
    2. Build a new certificate with the CA as issuer
    3. Sign TBS with Trezor
    4. Return PEM certificate
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    csr = x509.load_pem_x509_csr(csr_pem)

    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    now = datetime.now(timezone.utc)

    builder = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
    )

    # Copy SANs from CSR if present
    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    # Add authority key identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )

    # Add subject key identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False,
    )

    tbs_bytes = _get_tbs_bytes(builder, curve)
    _, sig = trezor_sign(session, uri, tbs_bytes, curve)
    der_sig = trezor_signature_to_der(sig, curve)
    cert_der = _assemble_cert_der(tbs_bytes, der_sig, curve)

    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_jwt(session, uri: str, claims: dict, curve: str = "ed25519",
             expires_in: int = 3600) -> str:
    """
    Sign a JWT using the Trezor.

    For ES256 (nist256p1): ECDSA P-256 + SHA-256
    For EdDSA (ed25519): Ed25519
    """
    if curve == "nist256p1":
        alg = "ES256"
    elif curve == "secp256k1":
        alg = "ES256K"
    elif curve == "ed25519":
        alg = "EdDSA"
    else:
        raise ValueError(f"Unsupported curve for JWT: {curve}")

    now = int(time.time())
    claims.setdefault("iat", now)
    claims.setdefault("exp", now + expires_in)

    header = {"alg": alg, "typ": "JWT"}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"

    _, sig = trezor_sign(session, uri, signing_input.encode(), curve)

    # Convert signature to JWS format
    raw_sig = sig[1:]  # strip 0x00 prefix

    if curve in ("nist256p1", "secp256k1"):
        # ES256 / ES256K: r || s, each 32 bytes (already in this format from Trezor)
        jws_sig = b64url(raw_sig[:64])
    elif curve == "ed25519":
        # EdDSA: raw 64-byte signature
        jws_sig = b64url(raw_sig[:64])

    return f"{signing_input}.{jws_sig}"


def export_jwk(session, uri: str, curve: str = "ed25519") -> dict:
    """Export the public key as a JWK for JWT verification."""
    pubkey = get_public_key(session, uri, curve)
    crypto_pubkey = pubkey_to_crypto_key(pubkey, curve)

    if curve == "nist256p1":
        numbers = crypto_pubkey.public_numbers()
        x_bytes = numbers.x.to_bytes(32, "big")
        y_bytes = numbers.y.to_bytes(32, "big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(x_bytes),
            "y": b64url(y_bytes),
            "use": "sig",
            "alg": "ES256",
        }
    elif curve == "secp256k1":
        numbers = crypto_pubkey.public_numbers()
        x_bytes = numbers.x.to_bytes(32, "big")
        y_bytes = numbers.y.to_bytes(32, "big")
        return {
            "kty": "EC",
            "crv": "secp256k1",
            "x": b64url(x_bytes),
            "y": b64url(y_bytes),
            "use": "sig",
            "alg": "ES256K",
        }
    elif curve == "ed25519":
        raw = pubkey[1:] if pubkey[0] == 0 else pubkey
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url(raw),
            "use": "sig",
            "alg": "EdDSA",
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_init_ca(args):
    """Initialize a new CA."""
    session = get_trezor_session()
    print(f"Deriving CA key from URI: {args.uri}", file=sys.stderr)
    print("Please confirm on your Trezor device...", file=sys.stderr)

    pem = build_ca_cert(session, args.uri, args.cn, args.curve, args.days)

    output = Path(args.output)
    output.write_bytes(pem)
    print(f"CA certificate written to {output}", file=sys.stderr)


def cmd_sign_csr(args):
    """Sign a CSR with the CA."""
    session = get_trezor_session()

    ca_pem = Path(args.ca_cert).read_bytes()
    csr_pem = Path(args.csr).read_bytes()

    print(f"Signing CSR with CA key from URI: {args.uri}", file=sys.stderr)
    print("Please confirm on your Trezor device...", file=sys.stderr)

    cert_pem = sign_csr(session, args.uri, ca_pem, csr_pem, args.curve, args.days)

    output = Path(args.output)
    output.write_bytes(cert_pem)
    print(f"Signed certificate written to {output}", file=sys.stderr)


def cmd_sign_jwt(args):
    """Sign a JWT."""
    session = get_trezor_session()

    claims = json.loads(args.claims)
    if args.sub:
        claims["sub"] = args.sub
    if args.aud:
        claims["aud"] = args.aud

    print(f"Signing JWT with key from URI: {args.uri}", file=sys.stderr)
    print("Please confirm on your Trezor device...", file=sys.stderr)

    token = sign_jwt(session, args.uri, claims, args.curve, args.expires)
    print(token)


def cmd_export_pubkey(args):
    """Export the public key."""
    session = get_trezor_session()

    print("Please confirm on your Trezor device...", file=sys.stderr)

    if args.format == "jwk":
        jwk = export_jwk(session, args.uri, args.curve)
        print(json.dumps(jwk, indent=2))
    elif args.format == "pem":
        pubkey = get_public_key(session, args.uri, args.curve)
        crypto_pubkey = pubkey_to_crypto_key(pubkey, args.curve)
        pem = crypto_pubkey.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print(pem.decode())


def cmd_gen_csr(args):
    """Generate a private key and CSR for a service (runs locally, no Trezor needed)."""
    key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
    ])

    builder = (
        CertificateSigningRequestBuilder()
        .subject_name(subject)
    )

    # Add SANs
    san_names = []
    for name in (args.san or []):
        try:
            san_names.append(IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            try:
                san_names.append(IPAddress(ipaddress.ip_network(name)))
            except ValueError:
                san_names.append(DNSName(name))

    if san_names:
        builder = builder.add_extension(
            SubjectAlternativeName(san_names),
            critical=False,
        )

    csr = builder.sign(key, hashes.SHA256())

    key_path = Path(args.key_out)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    print(f"Private key written to {key_path}", file=sys.stderr)

    csr_path = Path(args.output)
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    print(f"CSR written to {csr_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Trezor-backed PKI for k3s clusters and JWT signing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize CA
  %(prog)s init-ca --uri "gpg://ca@k3s.homelab" --cn "K3s Homelab CA"

  # Generate a service key + CSR
  %(prog)s gen-csr --cn "api.k3s.homelab" --san "api.k3s.homelab" --san "10.0.0.10"

  # Sign the CSR
  %(prog)s sign-csr --uri "gpg://ca@k3s.homelab" --ca-cert ca.crt --csr service.csr

  # Sign an admin JWT
  %(prog)s sign-jwt --uri "gpg://admin@k3s.homelab" --sub admin --claims '{"role":"cluster-admin"}'

  # Export public key for JWT verification
  %(prog)s export-pubkey --uri "gpg://admin@k3s.homelab" --format jwk
        """,
    )

    parser.add_argument("--curve", default="ed25519",
                        choices=["nist256p1", "secp256k1", "ed25519"],
                        help="Elliptic curve (default: ed25519)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-ca
    p_init = subparsers.add_parser("init-ca", help="Create a self-signed CA certificate")
    p_init.add_argument("--uri", required=True, help="gpg:// URI for CA identity")
    p_init.add_argument("--cn", required=True, help="Common Name for the CA")
    p_init.add_argument("--days", type=int, default=3650, help="Validity in days (default: 3650)")
    p_init.add_argument("--output", "-o", default="ca.crt", help="Output file (default: ca.crt)")
    p_init.set_defaults(func=cmd_init_ca)

    # gen-csr
    p_csr = subparsers.add_parser("gen-csr", help="Generate service key + CSR (local, no Trezor)")
    p_csr.add_argument("--cn", required=True, help="Common Name for the service")
    p_csr.add_argument("--san", action="append", help="Subject Alternative Name (repeatable)")
    p_csr.add_argument("--output", "-o", default="service.csr", help="CSR output (default: service.csr)")
    p_csr.add_argument("--key-out", default="service.key", help="Key output (default: service.key)")
    p_csr.set_defaults(func=cmd_gen_csr)

    # sign-csr
    p_sign = subparsers.add_parser("sign-csr", help="Sign a CSR with the Trezor CA")
    p_sign.add_argument("--uri", required=True, help="gpg:// URI for CA identity")
    p_sign.add_argument("--ca-cert", required=True, help="CA certificate file")
    p_sign.add_argument("--csr", required=True, help="CSR file to sign")
    p_sign.add_argument("--days", type=int, default=365, help="Validity in days (default: 365)")
    p_sign.add_argument("--output", "-o", default="service.crt", help="Output file (default: service.crt)")
    p_sign.set_defaults(func=cmd_sign_csr)

    # sign-jwt
    p_jwt = subparsers.add_parser("sign-jwt", help="Sign a JWT")
    p_jwt.add_argument("--uri", required=True, help="gpg:// URI for signing identity")
    p_jwt.add_argument("--sub", help="Subject claim")
    p_jwt.add_argument("--aud", help="Audience claim")
    p_jwt.add_argument("--claims", default="{}", help="Additional claims as JSON")
    p_jwt.add_argument("--expires", type=int, default=3600, help="Expiry in seconds (default: 3600)")
    p_jwt.set_defaults(func=cmd_sign_jwt)

    # export-pubkey
    p_pub = subparsers.add_parser("export-pubkey", help="Export public key")
    p_pub.add_argument("--uri", required=True, help="gpg:// URI for identity")
    p_pub.add_argument("--format", choices=["jwk", "pem"], default="jwk",
                       help="Output format (default: jwk)")
    p_pub.set_defaults(func=cmd_export_pubkey)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
