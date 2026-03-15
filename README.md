# trezor-pki

Hardware-backed Certificate Authority and JWT signing using a Trezor hardware wallet.

Uses the `SignIdentity` firmware feature (SLIP-0013) with `gpg://` URIs to produce raw Ed25519 signatures suitable for X.509 certificates and JWTs.

## How it works

`SignIdentity` with the `gpg://` protocol passes `challenge_hidden` bytes directly to the Ed25519 signing function on the device with no additional framing:

```python
# Trezor firmware (sign_identity.py)
if sigtype == "gpg":
    data = challenge_hidden
if curve == "ed25519":
    signature = ed25519.sign(seckey, data)
```

Key derivation is deterministic via SLIP-0013: a `gpg://` URI is hashed into a BIP-32 path. Same seed + same URI always produces the same key pair. Different URIs produce independent key pairs.

Every signing operation requires physical confirmation on the device.

## Requirements

```
pip install trezor cryptography
```

- Python 3.8+
- Trezor with `SignIdentity` support (Safe 3, Safe 5, Model T, Model One)
- Firmware 2.10.0+ recommended for Safe 3
- Ed25519 curve only (`nist256p1` returns `FirmwareError` on Safe 3 as of firmware 2.10.0)

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

```bash
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

```bash
python trezor-pki.py sign-csr \
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
- `nist256p1` returns `FirmwareError` on the Trezor Safe 3 (tested on firmware 2.6.4 and 2.10.0). `ed25519` works correctly.
- trezorlib 0.20+ requires `AppManifest` + `get_client()` + `client.get_session()`. The older `TrezorClient(transport, ui=...)` pattern no longer works.
- The `challenge_hidden` field supports up to 512 bytes.

## Compatibility

| Model | Firmware | ed25519 | nist256p1 |
|-------|----------|---------|-----------|
| Safe 3 (T2B1) | 2.10.0 | ✅ | ❌ FirmwareError |
| Model T | 2.1.0+ | Untested | Untested |
| Safe 5 | All | Untested | Untested |
| Model One | 1.3.4+ | Untested | Untested |

## License

MIT
