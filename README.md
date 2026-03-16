# trezor-pki

Hardware-backed Certificate Authority and JWT signing using a Trezor hardware wallet.

Uses the `SignIdentity` firmware feature (SLIP-0013) with `gpg://` URIs to produce raw signatures suitable for X.509 certificates and JWTs. Supports `ed25519`, `nist256p1` (P-256), and `secp256k1` (K-256) — use P-256 for browser-compatible CA certificates.

## How it works

`SignIdentity` with the `gpg://` protocol passes `challenge_hidden` bytes directly to the signing function with no additional framing:

```python
# Trezor firmware (sign_identity.py)
if sigtype == "gpg":
    data = challenge_hidden          # no pre-hashing by firmware
if curve == "ed25519":
    signature = ed25519.sign(seckey, data)    # hashes internally — any length OK
elif curve in ("nist256p1", "secp256k1"):
    signature = curve.sign(seckey, data)      # requires exactly 32 bytes
```

For `nist256p1` and `secp256k1`, `trezor-pki.py` SHA-256 hashes the TBS bytes before passing them to the firmware, matching the `ecdsa-with-SHA256` algorithm declared in the certificate.

Key derivation is deterministic via SLIP-0013: a `gpg://` URI is hashed into a BIP-32 path. Same seed + same URI always produces the same key pair. Different URIs produce independent key pairs.

Every signing operation requires physical confirmation on the device.

## Requirements

```
pip install trezor cryptography
```

- Python 3.8+
- Trezor with `SignIdentity` support (Safe 3, Safe 5, Model T, Model One)
- Firmware 2.10.0+ recommended for Safe 3
- `ed25519`, `nist256p1`, and `secp256k1` supported on Safe 3 (use `nist256p1` for browser-compatible certs)

### WSL2 USB passthrough

On Windows (PowerShell as admin):
```powershell
winget install usbipd
usbipd list                          # find Trezor BUSID (VID:PID 1209:53c1)
usbipd bind --busid <BUSID>
usbipd attach --wsl --busid <BUSID>
```

On WSL:
```bash
sudo apt install libusb-1.0-0-dev
sudo curl -o /etc/udev/rules.d/51-trezor.rules https://data.trezor.io/udev/51-trezor.rules
sudo chmod 666 /dev/bus/usb/001/*
sudo chmod 666 /dev/hidraw* /dev/trezor* 2>/dev/null
```

Trezor Suite must be closed on Windows before attaching. Permissions must be reset after every reattach.

## Usage

### Initialize a CA

Use `--curve nist256p1` for a browser-compatible CA (ecdsa-with-SHA256). Use `ed25519` for infrastructure-only (containerd, curl, Docker) where browser trust is not needed.

```bash
# Browser-compatible (recommended)
python trezor-pki.py --curve nist256p1 init-ca \
  --uri "gpg://ca@yourdomain" \
  --cn "My CA" \
  -o ca.crt

# Ed25519 (infrastructure only — not trusted by Firefox/Chrome in cert chains)
python trezor-pki.py init-ca \
  --uri "gpg://ca@yourdomain" \
  --cn "My CA" \
  -o ca.crt
```

### Generate a service key + CSR

No Trezor needed for this step.

```bash
python trezor-pki.py gen-csr \
  --cn "myservice.example.com" \
  --san "myservice.example.com" \
  --san "10.0.0.10" \
  -o service.csr \
  --key-out service.key
```

### Sign a CSR

Use the same `--curve` flag as when you created the CA.

```bash
python trezor-pki.py --curve nist256p1 sign-csr \
  --uri "gpg://ca@yourdomain" \
  --ca-cert ca.crt \
  --csr service.csr \
  -o service.crt
```

### Sign a JWT

```bash
python trezor-pki.py sign-jwt \
  --uri "gpg://admin@yourdomain" \
  --sub admin \
  --claims '{"role":"cluster-admin"}' \
  --expires 86400
```

### Export public key

```bash
python trezor-pki.py export-pubkey --uri "gpg://admin@yourdomain" --format jwk
python trezor-pki.py export-pubkey --uri "gpg://admin@yourdomain" --format pem
```

## URI namespacing

Each URI derives an independent key pair from the same seed:

| URI | Purpose |
|-----|---------|
| `gpg://ca@yourdomain` | Root CA signing |
| `gpg://admin@yourdomain` | Admin JWT signing |
| `gpg://deploy@yourdomain` | CI/CD token signing |

## Security properties

- CA private key never leaves the Trezor
- Deterministic key derivation — same seed + URI = same key, survives device replacement
- Physical confirmation required for every signature
- Seed backup via SLIP-39 Shamir secret sharing for M-of-N recovery
- Trezor displays the signing URI but does not interpret X.509 or JWT semantics — an airgapped signing machine mitigates substitution attacks

## Findings

- `SignIdentity` with `gpg://` sigtype is the only Trezor signing path that produces raw, unframed signatures. Bitcoin `signMessage` adds a message prefix, Cardano CIP-8 wraps in COSE_Sign1, and Solana does not support message signing.
- `nist256p1` works on Safe 3 but requires the `challenge_hidden` to be exactly 32 bytes — the firmware passes it directly to the ECDSA sign function which enforces this. `trezor-pki.py` handles this automatically by SHA-256 hashing the input before signing.
- `ed25519` CA certificates are rejected by Firefox and Chrome in TLS chain verification (`SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED` / `ERR_CERT_INVALID`). This is a browser limitation with no workaround — use `nist256p1` if browser trust is needed.
- trezorlib 0.20+ requires `AppManifest` + `get_client()` + `client.get_session()`. The older `TrezorClient(transport, ui=...)` pattern no longer works.
- The `challenge_hidden` field supports up to 512 bytes.

## Compatibility

| Model | Firmware | ed25519 | nist256p1 | secp256k1 |
|-------|----------|---------|-----------|-----------|
| Safe 3 (T2B1) | 2.10.0 | ✅ | ✅ | ✅ |
| Model T | 2.1.0+ | Untested | Untested | Untested |
| Safe 5 | All | Untested | Untested | Untested |
| Model One | 1.3.4+ | Untested | Untested | Untested |

## Testing

Integration tests live in `test_integration.py` and require a Trezor device connected and unlocked.

```bash
pip install pytest
pytest test_integration.py -v
```

Tests are parametrized over all three curves (`ed25519`, `nist256p1`, `secp256k1`). Each test that contacts the device requires a button press on the Trezor — expect around 27 confirmations for a full run.

To run a single curve:

```bash
pytest test_integration.py -v -k ed25519
```

If no device is found all tests are skipped automatically (no failure).

### What is tested

| Test | Description |
|------|-------------|
| `test_get_public_key_shape` | Correct byte length and SEC1/prefix format per curve |
| `test_sign_roundtrip` | Sign a message and verify the signature cryptographically |
| `test_public_key_is_deterministic` | Same URI + curve always returns the same key |
| `test_different_uris_give_different_keys` | Different URIs derive independent keys |
| `test_pubkey_to_crypto_key` | Public key converts to the correct cryptography library type |
| `test_build_ca_cert` | Self-signed CA cert is valid and has correct extensions |
| `test_sign_csr` | Leaf cert chain: issuer matches CA, BasicConstraints CA=false |
| `test_sign_jwt` | JWT structure and signature verify against the Trezor public key |
| `test_export_jwk` | JWK has correct `kty`, `crv`, `alg`, and coordinate sizes |

## License

MIT
