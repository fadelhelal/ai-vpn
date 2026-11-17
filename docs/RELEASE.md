# Release checklist

1. Run `npm test` and `npm run package:installer`.
2. Obtain a real OV or EV code-signing certificate and install Windows SDK Signing
   Tools. Never use a self-signed certificate for a public release.
3. Run `./scripts/sign-release.ps1 -CertificateThumbprint <thumbprint>`.
4. Keep the Ed25519 private key outside the project tree. By default the release
   command reads `%USERPROFILE%\\.aivpn-release\\release-signing.key`; set
   `AIVPN_RELEASE_KEY` to an absolute external path when the release machine
   uses another secret store. The command rejects a key path inside the project.
5. Run `npm run release:manifest` to create `dist/release.json` with SHA-256
   checksums and an Ed25519 signature. The command verifies the signature
   against the public key embedded in `src/release-key.js` before writing the
   file. Anyone holding the private key can sign a manifest the app accepts.
6. Upload the signed files, `release.json`, and the portable ZIP checksum over
   HTTPS under a versioned, access-controlled release location.
7. Automatic download/install remains disabled by design. The in-app check only
   reports a newer signed version; installation stays a manual, user-initiated
   step.

The release assets intentionally exclude all private `.ovpn` profiles, client
certificates, keys, passwords, and encrypted `%APPDATA%\\AIVPN` settings.
