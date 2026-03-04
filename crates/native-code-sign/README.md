# native-code-sign

Code signing wrappers using platform-native signing tools.

## macOS

Uses Apple's `codesign` tool.

Set the following environment variables:

- `CODESIGN_IDENTITY`: signing identity (e.g. "Developer ID Application: ...")
- `CODESIGN_CERTIFICATE`: base64-encoded .p12 certificate
- `CODESIGN_CERTIFICATE_PASSWORD`: password for the .p12
- `CODESIGN_OPTIONS`: (optional) extra `--options` value (e.g. `runtime` for hardened runtime / notarization)

An ephemeral keychain is used to store the certificate, temporarily modifying the keychain search
list. This modification is robust to concurrent `cargo-code-sign` invocations, but not to other
programs modifying the keychain search list.

## Windows

Uses Microsoft `signtool.exe`.

### Local certificate signing (.pfx)

Set the following environment variables:

- `SIGNTOOL_CERTIFICATE_PATH`: path to a .pfx certificate file
- `SIGNTOOL_CERTIFICATE_PASSWORD`: password for the .pfx
- `SIGNTOOL_TIMESTAMP_URL`: (optional) RFC 3161 timestamp server URL
- `SIGNTOOL_DESCRIPTION`: (optional) description shown in UAC prompts (signtool `/d` flag)
- `SIGNTOOL_PATH`: (optional) path to signtool.exe (defaults to `signtool.exe` from `PATH`)

### Azure Trusted Signing

Set all of:

- `SIGNTOOL_AZURE_DLIB_PATH`: path to `Azure.CodeSigning.Dlib.dll`
- `SIGNTOOL_AZURE_ENDPOINT`: Artifact Signing endpoint (for example `https://eus.codesigning.azure.net`)
- `SIGNTOOL_AZURE_ACCOUNT`: `CodeSigningAccountName`
- `SIGNTOOL_AZURE_CERTIFICATE_PROFILE`: `CertificateProfileName`

Optional:

- `SIGNTOOL_AZURE_CORRELATION_ID`: correlation ID for request tracing
- `SIGNTOOL_TIMESTAMP_URL`: RFC 3161 timestamp URL (defaults to `http://timestamp.acs.microsoft.com`)
- `SIGNTOOL_DESCRIPTION`: description shown in UAC prompts (`/d`)
- `SIGNTOOL_PATH`: explicit path to `signtool.exe`

Azure authentication is handled by the dlib via `DefaultAzureCredential`.
