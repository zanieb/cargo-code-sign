# native-code-sign

Code signing wrappers using platform-native signing tools.

## macOS

Uses Apple's `codesign` tool.

Set the following environment variables:

- `CODESIGN_IDENTITY`: signing identity (e.g. "Developer ID Application: ...")
- `CODESIGN_CERTIFICATE`: base64-encoded .p12 certificate
- `CODESIGN_CERTIFICATE_PASSWORD`: password for the .p12
- `CODESIGN_OPTIONS`: (optional) extra `--options` value (e.g. `runtime` for hardened runtime / notarization)
- `CODESIGN_ALLOW_UNTRUSTED`: (optional) set to `1`/`true` to allow self-signed certs not in system trust

All macOS variables also support a `_MACOS` suffix (for example `CODESIGN_CERTIFICATE_MACOS`).
When both are present, the suffixed variable takes precedence.

An ephemeral keychain is used to store the certificate, temporarily modifying the keychain search
list. This modification is robust to concurrent `cargo-code-sign` invocations, but not to other
programs modifying the keychain search list.

## Windows

Uses Microsoft `signtool.exe`.

### Local certificate signing (.pfx)

Set the following environment variables:

- `CODESIGN_CERTIFICATE_PATH`: path to a .pfx certificate file
- `CODESIGN_CERTIFICATE_PASSWORD`: password for the .pfx
- `CODESIGN_TIMESTAMP_URL`: (optional) RFC 3161 timestamp server URL
- `CODESIGN_DESCRIPTION`: (optional) description shown in UAC prompts (signtool `/d` flag)
- `CODESIGN_TOOL_PATH`: (optional) path to signtool.exe (defaults to `signtool.exe` from `PATH`)

All Windows variables also support a `_WINDOWS` suffix (for example `CODESIGN_CERTIFICATE_PATH_WINDOWS`).
When both are present, the suffixed variable takes precedence.

### Azure Trusted Signing

Set all of:

- `CODESIGN_AZURE_DLIB_PATH`: path to `Azure.CodeSigning.Dlib.dll`
- `CODESIGN_AZURE_ENDPOINT`: Artifact Signing endpoint (for example `https://eus.codesigning.azure.net`)
- `CODESIGN_AZURE_ACCOUNT`: `CodeSigningAccountName`
- `CODESIGN_AZURE_CERTIFICATE_PROFILE`: `CertificateProfileName`

Optional:

- `CODESIGN_AZURE_CORRELATION_ID`: correlation ID for request tracing
- `CODESIGN_TIMESTAMP_URL`: RFC 3161 timestamp URL (defaults to `http://timestamp.acs.microsoft.com`)
- `CODESIGN_DESCRIPTION`: description shown in UAC prompts (`/d`)
- `CODESIGN_TOOL_PATH`: explicit path to `signtool.exe`

Azure authentication is handled by the dlib via `DefaultAzureCredential`.
