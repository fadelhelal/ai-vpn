'use strict';

// Ed25519 public key for release manifests. The matching private key never
// lives in this tree: it is kept outside the project (default
// %USERPROFILE%\.aivpn-release\release-signing.key, override with
// AIVPN_RELEASE_KEY) and is never packaged.
module.exports = {
  RELEASE_PUBLIC_KEY: [
    '-----BEGIN PUBLIC KEY-----',
    'MCowBQYDK2VwAyEAlKMcj8yQlWQVPAyKO+2MoITEYamis2xUnWDokWfZblk=',
    '-----END PUBLIC KEY-----',
    ''
  ].join('\n')
};
