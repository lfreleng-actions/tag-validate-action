# SSH Test Keys

This directory contains example SSH public keys generated for testing the
`tag-validate` CLI tool's SSH key fingerprint parsing and normalization
capabilities.

The matching private keys are **not** committed. They were unencrypted
OpenSSH keys, which every secret-scanning tool flags on sight, and nothing
in the test suite read them: the tests and the shell script work from the
fingerprints recorded below. Regenerate them locally if you need them (see
[Regenerating Keys](#regenerating-keys)).

## Generated Keys

The following SSH key types have been generated for testing:

<!-- markdownlint-disable MD013 -->

| Key Type | Bit Size | Public Key File      | Description                    |
| -------- | -------- | -------------------- | ------------------------------ |
| RSA      | 2048     | `test_rsa_2048.pub`  | Standard RSA 2048-bit key      |
| RSA      | 4096     | `test_rsa_4096.pub`  | High-security RSA 4096-bit key |
| ECDSA    | 256      | `test_ecdsa_256.pub` | ECDSA P-256 curve              |
| ECDSA    | 384      | `test_ecdsa_384.pub` | ECDSA P-384 curve              |
| ECDSA    | 521      | `test_ecdsa_521.pub` | ECDSA P-521 curve              |
| Ed25519  | 256      | `test_ed25519.pub`   | Modern Ed25519 curve           |

<!-- markdownlint-enable MD013 -->

## Key Fingerprints

### SHA256 Fingerprints (Default Format)

```text
test_ecdsa_256:  SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14
test_ecdsa_384:  SHA256:lSpWQv6rFamTP2i93lIaLO8s8TZg/t06GsxrjQ5GAXY
test_ecdsa_521:  SHA256:oitgrhcEWqRZ248fv26IaaN8TT26bXTr6y65ylS/EcI
test_ed25519:    SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk
test_rsa_2048:   SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk
test_rsa_4096:   SHA256:xzmyjKD2ZBtadsgr2q0Bzu9B5sw4nAFeu69ZMb1MKNA
```

### MD5 Fingerprints (Legacy Format)

```text
test_ecdsa_256:  MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3
test_ecdsa_384:  MD5:e0:69:3e:84:68:47:10:31:2c:75:af:e5:c8:57:7a:13
test_ecdsa_521:  MD5:3f:18:4a:59:94:81:34:be:9e:54:92:d1:a1:51:8f:70
test_ed25519:    MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77
test_rsa_2048:   MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81
test_rsa_4096:   MD5:a1:1e:aa:33:b5:50:2c:16:3d:76:be:4c:03:70:5f:96
```

## Usage in Testing

These keys are used by the test script `scripts/test_ssh_keys.sh` to test
that the `tag-validate` CLI tool can:

1. **Parse different SSH fingerprint formats:**
   - `SHA256:...` (standard format)
   - `ECDSA:SHA256:...` (algorithm-prefixed)
   - `MD5:xx:xx:...` (legacy format)
   - `RSA:MD5:xx:xx:...` (algorithm-prefixed legacy)

2. **Handle full public key strings:**
   - `ssh-rsa AAAAB3...`
   - `ssh-ed25519 AAAAC3...`
   - `ecdsa-sha2-nistp256 AAAAE2...`

3. **Normalize inputs for GitHub API:**
   - Convert algorithm-prefixed formats to standard SHA256 format
   - Handle both MD5 and SHA256 hash formats
   - Extract fingerprints from full public keys

## Security Note

⚠️ **These are test keys for testing purposes!**

- All keys were generated with empty passphrases for testing purposes
- The public halves live in this repository; the private keys do not
- **NEVER use these keys for actual authentication or signing**
- These keys are not registered with any GitHub accounts
- The keys will fail GitHub verification (which is expected for testing)

## Generation Commands

The keys were generated using the following commands:

```bash
# RSA keys
ssh-keygen -t rsa -b 2048 -N "" -f test_rsa_2048 -C "test_rsa_2048"
ssh-keygen -t rsa -b 4096 -N "" -f test_rsa_4096 -C "test_rsa_4096"

# ECDSA keys
ssh-keygen -t ecdsa -b 256 -N "" -f test_ecdsa_256 -C "test_ecdsa_256"
ssh-keygen -t ecdsa -b 384 -N "" -f test_ecdsa_384 -C "test_ecdsa_384"
ssh-keygen -t ecdsa -b 521 -N "" -f test_ecdsa_521 -C "test_ecdsa_521"

# Ed25519 key
ssh-keygen -t ed25519 -N "" -f test_ed25519 -C "test_ed25519"
```

## Regenerating Keys

If you need to regenerate the test keys (e.g., for security reasons or testing
updates):

1. Delete the existing public keys: `rm -f test_*.pub`
2. Run the generation commands above in a directory outside the repository
3. Copy the `.pub` files back into this directory, leaving the private
   keys where they are
4. Update the fingerprints in this README, reading them with
   `ssh-keygen -lf <key>.pub` and `ssh-keygen -E md5 -lf <key>.pub`
5. Update the test script and unit tests with the new fingerprint values
