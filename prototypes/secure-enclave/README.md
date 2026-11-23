# Secure Enclave prototype

Checks the macOS unlock design: a device key created inside the Secure Enclave,
usable only after Touch ID or the Mac password, unwraps the user's account key.

- `KeysteadDeviceKey` (library): wraps the account key to the device key with HPKE
  (P-256, HKDF-SHA256, AES-256-GCM) and handles the Secure Enclave key. Meant to move
  into the app later.
- `se-proto` (command): runs the flow on this Mac.

```sh
swift test                       # wrapping tests, using software keys
swift run se-proto info          # Secure Enclave and Touch ID availability
swift run se-proto setup         # create the device key, wrap a new account key
swift run se-proto unlock        # approve, unwrap, compare, print timings
swift run se-proto reset         # delete the stored data
```

Data lives in `~/Library/Application Support/KeysteadPrototype` (override with
`KEYSTEAD_PROTO_DIR`). The device key file is a handle that only this Mac's Secure
Enclave can use; the account key itself is never stored, only a fingerprint of it.

Prototype limits: data is kept in files rather than the Keychain, because the Keychain
needs a signed app with entitlements.
