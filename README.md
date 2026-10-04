# Fidolizer

Fidolizer is a software FIDO2 authenticator. It speaks CTAPHID, CTAP 2.1, and U2F, and it keeps credential private keys in a local state file. A client can reach it in two ways: as a USB HID FIDO device, or, on macOS while System Integrity Protection stays on, through a Chrome extension that forwards `navigator.credentials.create` and `get`.

Its AAGUID is `7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10`. That value identifies this program. It is not a YubiKey AAGUID and it is not enrolled in the FIDO metadata service.

**Contents**

- [Requirements](#requirements)
- [Build](#build)
- [Commands](#commands)
- [State](#state)
- [HID device](#hid-device)
- [Chrome while SIP stays on](#chrome-while-sip-stays-on)
- [What the authenticator implements](#what-the-authenticator-implements)
- [Source layout](#source-layout)
- [Testing](#testing)
- [Boundaries](#boundaries)

## Requirements

| Requirement | Notes |
|---|---|
| C++23 compiler | Clang or GCC. The Makefile defaults to `clang++`; pass `CXX=` to override. |
| CMake 3.24+ | The Makefile configures and builds. CMake is the real build system. |
| OpenSSL 3 | `libcrypto`. On macOS with Homebrew, CMake looks in `/opt/homebrew/opt/openssl@3`. |
| macOS or Linux | macOS HID uses `IOHIDUserDevice`. Linux HID uses `/dev/uhid`. |

The CTAP stack, the WebAuthn JSON boundary, and `make test` do not need a HID device, a signing identity, or a disabled SIP.

## Build

```sh
make
make test
make install PREFIX=$HOME/.local
```

`make` configures `build/` as Release and compiles `build/fidolizer` and `build/fidolizer_tests`. `make install` puts the `fidolizer` binary and the `fidolizer-webauthn` host launcher in `PREFIX/bin`, and the unpacked Chrome extension in `PREFIX/share/fidolizer/extension`.

| Target | Effect |
|---|---|
| `make`, `make build` | Configure if needed, then build the binary and the tests |
| `make test` | Build, run the CTAP suite through CTest, then the extension origin test |
| `make run` | `build/fidolizer serve` |
| `make install` | Install into `PREFIX` (default `/usr/local`) |
| `make uninstall` | Remove the installed binary, host launcher, and data directory |
| `make clean` | Remove build products and keep the CMake cache |
| `make distclean` | Delete `build/` |

Useful variables: `PREFIX`, `BUILD_DIR`, `BUILD_TYPE` (`Release` or `Debug`), `CXX`, `JOBS`.

## Commands

```text
fidolizer [serve] [options]
fidolizer webauthn [options]
fidolizer info [options]
fidolizer set-pin [options]
fidolizer change-pin [options]
fidolizer reset --yes [options]
fidolizer credentials [options]
fidolizer delete <credential-id-hex> [options]
```

| Option | Meaning |
|---|---|
| `--state PATH` | State file. Default `$FIDOLIZER_STATE`, or `~/.fidolizer/authenticator.cbor` |
| `--up MODE` | `prompt` (default), `auto`, or `deny`. `FIDOLIZER_UP` sets the same default |
| `--vid 0xNNNN` | USB vendor id for `serve`. Default `0x1209` (pid.codes) |
| `--pid 0xNNNN` | USB product id for `serve`. Default `0xF1D2` |
| `--pin PIN` | New PIN for `set-pin` and `change-pin`. Omitted, the command reads it from the terminal with echo off |
| `--old-pin PIN` | Current PIN for `change-pin` |
| `--yes` | Required by `reset` |
| `-h`, `--help` | Print the same summary |

`serve` stays in the foreground and handles CTAP until SIGINT or SIGTERM. The HID device exists only while that process is running.

`info` prints the state path, AAGUID, serial, whether a PIN is set, the PIN retry counter, the minimum PIN length, the resident-credential count, the global counter, and the default USB ids.

`credentials` lists discoverable credentials as `id-hex  rp-id  user-name  count N`. `delete` removes one discoverable credential by that hex id. Wrapped non-discoverable credentials live inside the credential id the relying party already stored; they do not appear in this list.

`set-pin` and `change-pin` accept a PIN of 4 to 63 bytes. `reset --yes` deletes every credential, the PIN, and the attestation key, then writes a new state file.

`--up auto` approves presence and built-in user verification immediately. `--up deny` refuses both. The default `prompt` is a dialog on macOS and a terminal prompt elsewhere. Tests and unattended Chrome use `auto`.

## State

The state file is CBOR, mode `0600`. Opening it creates the parent directory and the file when they are missing. It holds:

- credential private keys for discoverable credentials
- the wrap key used to seal non-discoverable credential ids
- the attestation private key and its self-signed certificate
- the PIN hash, retry counter, and minimum PIN length
- the AAGUID and the serial string

Treat the file as the authenticator. Copying it copies every credential. `fidolizer` never prints private keys.

## HID device

`serve` registers a USB HID FIDO device: usage page `0xF1D0`, usage `0x01`, 64-byte input and output reports, the report descriptor from the CTAP 2.1 USB transport. The advertised manufacturer and product are `Fidolizer` and `Fidolizer FIDO2`.

### Linux

The device node is `/dev/uhid`, created with `UHID_CREATE2` on the USB bus. Open that node as root or as a user in the `uhid` group.

```sh
fidolizer serve
```

`ssh -sk`, `libfido2`, browsers, and other clients that enumerate HID FIDO devices can then see it.

### macOS

Creation goes through `IOHIDUserDeviceCreateWithProperties`. macOS allows that only for a binary signed with the restricted entitlement `com.apple.developer.hid.virtual.device`. The entitlement is not in a normal Apple Development or Developer ID profile. Ad-hoc signing it does not help: with System Integrity Protection on, AMFI kills the process. Without the entitlement the create call returns NULL, and `serve` exits.

When Apple has authorized the entitlement on the App ID:

```sh
codesign --force --sign "Apple Development: …" \
  --entitlements cmake/fidolizer.entitlements build/fidolizer
build/fidolizer serve
```

`cmake/fidolizer.entitlements` requests only that one entitlement. Root does not bypass the check. Turning SIP off is not a configuration this repository documents or performs.

There is no `/dev/uhid` on macOS. `RemoteHID`, `rapportd`, and the other system HID agents are not a client API for creating a FIDO device.

## Chrome while SIP stays on

Chrome 115 and later can hand WebAuthn create and get to one unpacked extension. `extension/` is that extension. It calls `chrome.webAuthenticationProxy.attach()`, handles `onCreateRequest`, `onGetRequest`, and `onIsUvpaaRequest`, and forwards create and get to `fidolizer webauthn` over native messaging. `isUvpaa` is answered in the extension, as true, so Chrome treats the result as a platform authenticator.

This path does not create a HID device. Safari, Firefox, `ssh -sk`, and `libfido2` still need `serve` and, on macOS, the virtual-HID entitlement. Only one extension can hold `webAuthenticationProxy`. Chrome Remote Desktop uses the same slot.

```sh
make
```

1. Open `chrome://extensions`, enable Developer mode, and load `extension/` unpacked.
2. Copy `extension/com.fidolizer.webauthn.json` to the browser's `NativeMessagingHosts` directory. For Google Chrome on macOS that is `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`. Chromium, Chrome Canary, Brave, and the Linux and Windows hosts each have their own directory.
3. Set `path` in the copied file to the absolute path of `extension/fidolizer-webauthn`. The committed file keeps the placeholder `/ABSOLUTE/PATH/TO/fidolizer/extension/fidolizer-webauthn` so a checkout does not record one machine's home directory.
4. Restart the browser.

The extension id pinned by the manifest `key` is `dhakjbimnhkkehfjbklbmlacpphjpkdp`. The host manifest's `allowed_origins` already names `chrome-extension://dhakjbimnhkkehfjbklbmlacpphjpkdp/`. The host name is `com.fidolizer.webauthn`.

`extension/fidolizer-webauthn` is the program Chrome launches. Chrome passes no arguments, so the script execs `fidolizer webauthn`. It uses `$FIDOLIZER_BIN` when that is set, then a `fidolizer` next to the script, then `../build/fidolizer`. Presence for that process follows `--up` / `FIDOLIZER_UP`; unattended use wants `FIDOLIZER_UP=auto`.

### What crosses the native-messaging pipe

Each message is a 4-byte little-endian length followed by one JSON object. The extension sends:

```json
{
  "type": "create",
  "origin": "https://example.com",
  "crossOrigin": false,
  "topOrigin": "https://example.com",
  "request": {}
}
```

`type` is `create` or `get`. `request` is Chrome's `requestDetailsJson`: the PublicKeyCredential creation or request options, with byte fields already base64url. Chrome does not put the page origin in that object.

The extension learns the origin itself. A page-world hook in the frame that is about to call `navigator.credentials.create` or `get` tells the service worker, and the worker waits for that report before the real call proceeds. If no calling frame has reported, the worker uses the active tab's top origin. An iframe that only loaded does not replace the page. `crossOrigin` is true when the caller and the tab top origin differ; `topOrigin` is then included in `clientDataJSON`.

The reply is `PublicKeyCredential.toJSON()`:

- `id` and `rawId` are the same base64url credential id
- `type` is `public-key`
- `authenticatorAttachment` is `platform`
- `response.clientDataJSON` carries `type` (`webauthn.create` or `webauthn.get`), the challenge string from the request, and the caller origin
- a create response carries a packed attestation object, `authenticatorData`, the SPKI `publicKey`, `publicKeyAlgorithm` `-7`, and `transports: ["internal"]`
- a get response carries `authenticatorData` and `signature`
- `userHandle` is the base64url user id when CTAP returned a user, which is a discoverable credential verified with UV. A non-resident get omits `userHandle`. Chrome rejects a JSON null in that field

On failure the reply is `{"error":{"name":"…","message":"…"}}` and the extension completes the Chrome request with that DOMException name.

`clientDataHash` is SHA-256 of the exact `clientDataJSON` bytes. Attestation is packed basic: the signature is over `authenticatorData || clientDataHash` and verifies with the certificate in `attStmt.x5c`. An assertion signature verifies with the credential public key. The AAGUID inside attested authenticator data is `7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10`, at offset 37.

The WebAuthn boundary maps `residentKey` `required` or `preferred` to CTAP `rk`, and `discouraged` or an absent value to no resident key unless `requireResidentKey` is true. `userVerification` `required`, `preferred`, or absent becomes CTAP `uv`; `discouraged` does not. Built-in UV is the presence prompt (`--up`). A resident credential requested without UV is refused here, because this path does not run the PIN protocol. Discoverable credentials are what `credentials` lists and what the state file stores as credentials. Non-discoverable credentials are wrapped into the credential id.

## What the authenticator implements

- CTAPHID: INIT, CBOR, MSG, PING, WINK, LOCK, CANCEL, KEEPALIVE, ERROR, and multi-packet messages up to 7609 bytes
- CTAP 2.1: MakeCredential, GetAssertion, GetNextAssertion, GetInfo, ClientPIN, Reset, Selection, CredentialManagement (`0x0A` and preview `0x41`)
- PIN/UV protocols 1 and 2, including `getPinUvAuthTokenUsingPinWithPermissions`
- built-in user verification through the local approval prompt
- discoverable credentials, up to 128, and wrapped non-discoverable credential ids
- `makeCredUvNotRqd`, so a non-discoverable credential can be created with user presence only
- packed basic attestation, ES256 (`alg -7`), self-signed, with the FIDO AAGUID certificate extension
- extensions: `credProtect`, `hmac-secret`, `credBlob`
- U2F register, authenticate, and version over CTAPHID MSG
- transports advertised by GetInfo: `usb`. The Chrome path reports `internal` on the WebAuthn credential because that is how Chrome classifies a UVPA platform authenticator

GetInfo versions are `U2F_V2`, `FIDO_2_0`, and `FIDO_2_1`. Options include `rk`, `up`, `uv`, `clientPin`, `pinUvAuthToken`, `makeCredUvNotRqd`, and `credentialMgmtPreview`. `plat` is false on the CTAP device. The minimum PIN length starts at 4.

## Source layout

| Path | Role |
|---|---|
| `src/authenticator.cpp` | CTAP 2.1 and U2F. The WebAuthn path calls this unchanged |
| `src/ctaphid.cpp` | CTAPHID packet assembly and commands |
| `src/hid_linux.cpp`, `src/hid_macos.mm` | `/dev/uhid` and `IOHIDUserDevice` |
| `src/webauthn.cpp` | Origin, `clientDataJSON`, CTAP options, and `PublicKeyCredential` JSON |
| `src/store.cpp` | CBOR state file, mode `0600` |
| `src/crypto.cpp` | P-256, SHA-256, HMAC, PIN key derivation |
| `src/cbor.cpp`, `src/json.cpp` | In-tree CBOR and JSON. No third-party parser |
| `src/presence.cpp` | `prompt`, `auto`, and `deny` |
| `src/main.cpp` | CLI and the native-messaging frame |
| `include/fidolizer/identity.hpp` | AAGUID, USB ids, HID report descriptor |
| `extension/` | Manifest V3 `webAuthenticationProxy` extension and the host launcher |
| `tests/test_authenticator.cpp` | CTAP suite and the WebAuthn create/get checks |
| `cmake/fidolizer.entitlements` | The macOS virtual-HID entitlement plist |

## Testing

```sh
make test
```

CTest runs `fidolizer_tests`. The suite drives the authenticator in process, with a temporary state file and `--up auto`'s presence mode. It covers CBOR and crypto primitives, make-credential and get-assertion, packed attestation, PIN protocol 2, resident keys, hmac-secret, credential management, U2F, and multi-packet CTAPHID.

The WebAuthn checks call `transactWebAuthn`, the same function `fidolizer webauthn` calls. They create a credential and then get it, and they check `clientDataJSON` type, challenge, and origin, the ES256 attestation and assertion signatures, the AAGUID bytes, and state mode `0600`. A second case uses `residentKey: "discouraged"` and checks that the assertion JSON has no `userHandle` while the signature still verifies.

`make test` then runs `node extension/origin-select.test.js`. That test loads `extension/origin-select.js`, the function the service worker uses to choose the caller origin, and checks that an iframe load does not replace the tab's top origin and that a frame which actually called WebAuthn does.

`make test` does not sign a binary, open a HID device, launch Chrome, or change SIP.

## Boundaries

- macOS `serve` does nothing useful until Apple has authorized `com.apple.developer.hid.virtual.device` for the signing identity. SIP stays on.
- The Chrome path is create, get, and `isUvpaa` for pages Chrome gives to `webAuthenticationProxy`. It is not Safari, Firefox, `ssh -sk`, `libfido2`, U2F, or CTAP credential management.
- The AAGUID stays `7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10`.
- Attestation is packed basic with a self-signed certificate. Relying parties that require an attestation CA in the FIDO metadata service will reject it.
- One process owns the state file. Two `serve` or `webauthn` processes on the same path will race.
- The state file is the credential store. Filesystem access to it is access to the keys.
