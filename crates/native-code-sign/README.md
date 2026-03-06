# native-code-sign

Code signing wrappers using platform-native signing tools.

## macOS

Uses Apple's `codesign` tool.

Set the following environment variables:

- `CODE_SIGN_IDENTITY`: signing identity (e.g. "Developer ID Application: ...")
- `CODE_SIGN_CERTIFICATE`: base64-encoded .p12 certificate
- `CODE_SIGN_CERTIFICATE_PASSWORD`: password for the .p12
- `CODE_SIGN_OPTIONS`: (optional) extra `--options` value (e.g. `runtime` for hardened runtime / notarization)
- `CODE_SIGN_ALLOW_UNTRUSTED`: (optional) set to `1`/`true` to allow self-signed certs not in system trust

An ephemeral keychain is used to store the certificate, temporarily modifying the keychain search
list. This modification is robust to concurrent `cargo-code-sign` invocations, but not to other
programs modifying the keychain search list.

## Windows

Uses Microsoft `signtool.exe`.

### Local certificate signing (.pfx)

Set the following environment variables:

- `CODE_SIGN_CERTIFICATE_PATH`: path to a .pfx certificate file
- `CODE_SIGN_CERTIFICATE_PASSWORD`: password for the .pfx
- `CODE_SIGN_TIMESTAMP_URL`: (optional) RFC 3161 timestamp server URL
- `CODE_SIGN_DESCRIPTION`: (optional) description shown in UAC prompts (signtool `/d` flag)
- `CODE_SIGN_TOOL_PATH`: (optional) path to signtool.exe (defaults to `signtool.exe` from `PATH`)

### Azure Trusted Signing

Set all of:

- `CODE_SIGN_AZURE_DLIB_PATH`: path to `Azure.CodeSigning.Dlib.dll`
- `CODE_SIGN_AZURE_ENDPOINT`: Artifact Signing endpoint (for example `https://eus.codesigning.azure.net`)
- `CODE_SIGN_AZURE_ACCOUNT`: `CodeSigningAccountName`
- `CODE_SIGN_AZURE_CERTIFICATE_PROFILE`: `CertificateProfileName`

Optional:

- `CODE_SIGN_AZURE_CORRELATION_ID`: correlation ID for request tracing
- `CODE_SIGN_TIMESTAMP_URL`: RFC 3161 timestamp URL (defaults to `http://timestamp.acs.microsoft.com`)
- `CODE_SIGN_DESCRIPTION`: description shown in UAC prompts (`/d`)
- `CODE_SIGN_TOOL_PATH`: explicit path to `signtool.exe`

Azure authentication is handled by the dlib via `DefaultAzureCredential`.
