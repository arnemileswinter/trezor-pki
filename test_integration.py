"""
Integration tests for trezor-pki.py — requires a Trezor device connected via USB.

Run with:
    pytest test_integration.py -v

The tests exercise all three supported curves (ed25519, nist256p1, secp256k1)
against a live device. Each test that touches the Trezor will prompt for
confirmation on the device.
"""

import hashlib
import json
import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import CertificateSigningRequestBuilder
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Patch sys.path so we can import from trezor-pki.py (hyphen in filename)
# ---------------------------------------------------------------------------
import importlib.util, pathlib

_src = pathlib.Path(__file__).parent / "trezor-pki.py"
_spec = importlib.util.spec_from_file_location("trezor_pki", _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

get_trezor_session = _mod.get_trezor_session
trezor_sign = _mod.trezor_sign
get_public_key = _mod.get_public_key
pubkey_to_crypto_key = _mod.pubkey_to_crypto_key
trezor_signature_to_der = _mod.trezor_signature_to_der
build_ca_cert = _mod.build_ca_cert
sign_csr = _mod.sign_csr
sign_jwt = _mod.sign_jwt
export_jwk = _mod.export_jwk


# ---------------------------------------------------------------------------
# Shared session fixture (one device connection for the whole test run)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def session():
    """Connect to the Trezor once for the entire test session."""
    try:
        s = get_trezor_session()
    except Exception as exc:
        pytest.skip(f"No Trezor device found: {exc}")
    return s


CURVES = ["ed25519", "nist256p1", "secp256k1"]

# One stable URI per curve so each curve derives a different key.
def uri(curve: str) -> str:
    return f"gpg://test-{curve}@integration.test"


# ---------------------------------------------------------------------------
# Helper: verify an ECDSA signature with the cryptography library
# ---------------------------------------------------------------------------

def _verify_ecdsa(pubkey_bytes: bytes, curve: str, message: bytes, der_sig: bytes):
    """Verify a DER-encoded ECDSA signature against the raw message."""
    crypto_pub = pubkey_to_crypto_key(pubkey_bytes, curve)
    digest = hashlib.sha256(message).digest()
    # low-level verify: pass prehash + Prehashed
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    crypto_pub.verify(der_sig, digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))


def _verify_ed25519(pubkey_bytes: bytes, message: bytes, raw_sig: bytes):
    """Verify a raw Ed25519 signature against the raw message."""
    crypto_pub = pubkey_to_crypto_key(pubkey_bytes, "ed25519")
    crypto_pub.verify(raw_sig, message)


# ---------------------------------------------------------------------------
# 1. get_public_key — sanity-check key shape for each curve
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_get_public_key_shape(session, curve):
    """get_public_key returns bytes of the expected length for each curve."""
    pubkey = get_public_key(session, uri(curve), curve)

    assert isinstance(pubkey, bytes), "public key must be bytes"

    if curve == "ed25519":
        # 0x00 prefix + 32-byte key
        assert len(pubkey) == 33, f"ed25519 pubkey should be 33 bytes, got {len(pubkey)}"
        assert pubkey[0] == 0x00, "ed25519 pubkey should start with 0x00"
    else:
        # Compressed SEC1: 33 bytes starting with 02 or 03
        assert len(pubkey) == 33, f"{curve} pubkey should be 33 bytes, got {len(pubkey)}"
        assert pubkey[0] in (0x02, 0x03), f"{curve} pubkey should be compressed SEC1"


# ---------------------------------------------------------------------------
# 2. trezor_sign — basic sign + verify round-trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_sign_roundtrip(session, curve):
    """Sign a test message and verify the signature cryptographically."""
    message = f"hello trezor-pki curve={curve}".encode()
    pubkey, sig = trezor_sign(session, uri(curve), message, curve)

    # Signature must start with 0x00 per firmware convention
    assert sig[0] == 0x00, "Trezor signature should start with 0x00"
    assert len(sig) >= 65, "Signature too short"

    der_sig = trezor_signature_to_der(sig, curve)

    if curve == "ed25519":
        _verify_ed25519(pubkey, message, der_sig)
    else:
        _verify_ecdsa(pubkey, curve, message, der_sig)


# ---------------------------------------------------------------------------
# 3. Deterministic key — same URI + curve always returns the same public key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_public_key_is_deterministic(session, curve):
    """Two calls with the same URI and curve must return the same public key."""
    pk1 = get_public_key(session, uri(curve), curve)
    pk2 = get_public_key(session, uri(curve), curve)
    assert pk1 == pk2, "Public key should be deterministic for a given URI + curve"


# ---------------------------------------------------------------------------
# 4. Different URIs → different keys
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_different_uris_give_different_keys(session, curve):
    """Two different URIs must derive different keys."""
    pk1 = get_public_key(session, uri(curve), curve)
    pk2 = get_public_key(session, f"gpg://other-{curve}@integration.test", curve)
    assert pk1 != pk2, "Different URIs should yield different keys"


# ---------------------------------------------------------------------------
# 5. pubkey_to_crypto_key — round-trip through cryptography library
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_pubkey_to_crypto_key(session, curve):
    """pubkey_to_crypto_key produces a usable public key object."""
    pubkey = get_public_key(session, uri(curve), curve)
    crypto_pub = pubkey_to_crypto_key(pubkey, curve)

    if curve == "ed25519":
        assert isinstance(crypto_pub, ed25519.Ed25519PublicKey)
        # Re-export and compare raw bytes
        raw = crypto_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert raw == pubkey[1:]
    else:
        assert isinstance(crypto_pub, ec.EllipticCurvePublicKey)
        expected_curve = ec.SECP256R1 if curve == "nist256p1" else ec.SECP256K1
        assert isinstance(crypto_pub.curve, expected_curve)


# ---------------------------------------------------------------------------
# 6. CA certificate creation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_build_ca_cert(session, curve):
    """build_ca_cert returns a valid self-signed PEM certificate."""
    pem = build_ca_cert(session, uri(curve), f"Test CA ({curve})", curve, days=1)

    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(pem)

    # Basic constraints: must be a CA
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True

    # Subject == Issuer (self-signed)
    assert cert.subject == cert.issuer

    # Common name matches
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == f"Test CA ({curve})"


# ---------------------------------------------------------------------------
# 7. Sign CSR with CA
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_sign_csr(session, curve):
    """build_ca_cert + sign_csr produces a verifiable certificate chain."""
    ca_pem = build_ca_cert(session, uri(curve), f"Test CA ({curve})", curve, days=1)

    # Generate a local service key + CSR
    svc_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "service.test"),
        ]))
        .sign(svc_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    cert_pem = sign_csr(session, uri(curve), ca_pem, csr_pem, curve, days=1)

    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Issuer of leaf == subject of CA
    ca_cert = x509.load_pem_x509_certificate(ca_pem)
    assert cert.issuer == ca_cert.subject

    # Not a CA
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is False


# ---------------------------------------------------------------------------
# 8. JWT sign + structural verification
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@pytest.mark.parametrize("curve", CURVES)
def test_sign_jwt(session, curve):
    """sign_jwt produces a well-formed JWT with a valid signature."""
    claims = {"sub": "test-user", "aud": "test-audience"}
    token = sign_jwt(session, uri(curve), claims, curve, expires_in=60)

    parts = token.split(".")
    assert len(parts) == 3, "JWT must have 3 parts"

    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))

    expected_alg = {"ed25519": "EdDSA", "nist256p1": "ES256", "secp256k1": "ES256K"}[curve]
    assert header["alg"] == expected_alg
    assert header["typ"] == "JWT"
    assert payload["sub"] == "test-user"
    assert payload["aud"] == "test-audience"
    assert "iat" in payload
    assert "exp" in payload

    # Verify the signature cryptographically
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    raw_sig = _b64url_decode(parts[2])
    pubkey = get_public_key(session, uri(curve), curve)

    if curve == "ed25519":
        _verify_ed25519(pubkey, signing_input, raw_sig)
    else:
        # ES256/ES256K: sig is r||s, need DER for cryptography lib
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der_sig = encode_dss_signature(r, s)
        digest = hashlib.sha256(signing_input).digest()
        from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
        crypto_pub = pubkey_to_crypto_key(pubkey, curve)
        crypto_pub.verify(der_sig, digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))


# ---------------------------------------------------------------------------
# 9. JWK export
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("curve", CURVES)
def test_export_jwk(session, curve):
    """export_jwk returns a well-formed JWK for each curve."""
    jwk = export_jwk(session, uri(curve), curve)

    if curve == "nist256p1":
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["alg"] == "ES256"
        assert "x" in jwk and "y" in jwk
        assert len(_b64url_decode(jwk["x"])) == 32
        assert len(_b64url_decode(jwk["y"])) == 32
    elif curve == "secp256k1":
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "secp256k1"
        assert jwk["alg"] == "ES256K"
        assert "x" in jwk and "y" in jwk
        assert len(_b64url_decode(jwk["x"])) == 32
        assert len(_b64url_decode(jwk["y"])) == 32
    elif curve == "ed25519":
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["alg"] == "EdDSA"
        assert "x" in jwk
        assert len(_b64url_decode(jwk["x"])) == 32
