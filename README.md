# actions-openpubkey-signer

This action generates an ephemeral public/private keypair, signs things with private key, and uses OIDC to prove posession of the associated public key

Based on https://eprint.iacr.org/2023/296.pdf

But with two notable differences:

1. To work on GitHub actions, the 'audience' claim is used
2. The signature itself is added to the audience too. This ensures that if the key pair can only be used once.

## How to use this Action

To use this Action in another repository, you must checkout this Action repo and then run it.
Here's an example of how that is done:

```yaml

on: [pull_request]

jobs:
  oidc_sign:
    permissions:
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    name: sign binary
    steps:
      - name: Checkout actions-openpubkey-signer
        uses: actions/checkout@v3
        with:
          repository: kipz/actions-openpubkey-signer
          ref: main
          #token: ${{ secrets.your-checkout-token }}
          path: ./.github/actions/actions-openpubkey-signer
      - name: Sign with OpenPubKey
        uses: ./.github/actions/actions-openpubkey-signer
        with:
          message: 'digest-to-sign'
```
