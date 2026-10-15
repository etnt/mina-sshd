# OQS-OpenSSH test container (pure ML-KEM and pure ML-DSA)

Interoperability test server for GH-928. It runs the Open Quantum Safe fork of OpenSSH
(branch `OQS-v10`, OpenSSH 10.3p1 based) on Alpine.

## What it supports

- Pure ML-KEM key exchange, with the names of `draft-harrison-sshm-mlkem`:
  `mlkem512-sha256`, `mlkem768-sha256`, `mlkem1024-sha384`.
  (Hybrids such as `mlkem768x25519-sha256` are also in the binary, but `sshd_config` does not enable them.)
- Pure ML-DSA host and user keys, with the names of `draft-sfluhrer-ssh-mldsa`:
  `ssh-mldsa-44`, `ssh-mldsa-65`, `ssh-mldsa-87`.
- OQS composite keys (`ssh-rsa3072-mldsa-44`, ...). These are **not** the same as the
  `ssh-mldsa44-ed25519` of OpenSSH 10.5. Do not use them for that test.

## Maintainer requirements (GH-928 comment 6190939136)

| Requirement | Status |
|---|---|
| SSH server with pure ML-KEM | Yes (checked) |
| Small | 30 MB (arm64, measured). Alpine runtime stage only; no compiler. |
| Multi-arch (x86_64 and arm64) | Dockerfile has no arch-specific code. **Only arm64 was built and run.** amd64 must still be built with `buildx` and checked. |
| No compile or heavy base at test time | Compilation happens once in the image build. Tests must pull a **prebuilt, published** image. |

## Checked on arm64 (podman)

- `ssh -Q kex` in the container lists `mlkem768-sha256` and the other pure names.
- `ssh -Q key` lists `ssh-mldsa-44/65/87`.
- A connection with `KexAlgorithms=mlkem768-sha256`, `HostKeyAlgorithms=ssh-mldsa-65` and a
  `ssh-mldsa-44` user key authenticated and ran a command.

## Build and run

```
docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/mina-sshd-oqs-openssh:<tag> --push .
docker run --rm -p 2222:22 <registry>/mina-sshd-oqs-openssh:<tag>
```

- User `test`, password `test` (override with the `TEST_PASSWORD` environment variable).
- Public keys: write `/home/test/.ssh/authorized_keys` (Testcontainers `withCopyToContainer`).
  The file must belong to `test` with mode 600.
- Host keys are generated at first start. Read the `.pub` files from `/etc/ssh` to build `known_hosts`.

## Quick sanity test

Automatic test (works with a local or a published image):

```
./smoke-test.sh ghcr.io/<owner>/mina-sshd-oqs-openssh:dev docker   # or: podman
```

It prints `ALL OK` at the end. It checks the algorithm lists, then opens sessions with both pure
ML-KEM key exchanges and all three ML-DSA host keys, using an `ssh-mldsa-44` user key.

Manual test:

1. Start the server: `docker run -d --name oqs -p 2222:22 <image>`
2. Check that it only offers pure ML-KEM. A stock OpenSSH client must be **refused**:
   `ssh -p 2222 test@localhost true`
   Expected: `no matching key exchange method found. Their offer: mlkem768-sha256,mlkem1024-sha384,mlkem512-sha256,...`
3. Connect with the client that is inside the image. It supports the pure algorithms:
   ```
   docker exec -u test oqs ssh-keygen -q -t ssh-mldsa-44 -N '' -f /home/test/.ssh/id
   docker exec -u test oqs sh -c 'cp ~/.ssh/id.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
   docker exec -u test oqs ssh -v -o StrictHostKeyChecking=no \
       -o KexAlgorithms=mlkem768-sha256 -o HostKeyAlgorithms=ssh-mldsa-65 \
       -o PubkeyAcceptedAlgorithms=ssh-mldsa-44 -i /home/test/.ssh/id localhost echo OK
   ```
   Expected in the output: `kex: algorithm: mlkem768-sha256`, `Server host key: ssh-mldsa-65` and `OK`.
4. Stop it: `docker rm -f oqs`

## Known problems and open points

1. **Pinned to a fork.** The pins are `LIBOQS_REF` and `OQS_OPENSSH_REF` (build arguments).
   The fork says it is experimental. The maintainer asked for a reputable implementation. Decide
   with him if OQS is acceptable. No other implementation with pure ML-KEM was found.
2. **GCC 14 workaround.** The fork calls `sshkey_clear_pkey()` without a prototype.
   `-Wno-error=implicit-function-declaration` hides it, as the fork's own CI does.
3. **liboqs is not trimmed.** `OQS_MINIMAL_BUILD` breaks the build, because `ssh-oqs.c` references
   many signature algorithms. So `/opt/oqs` is the largest part of the image.
4. **Prebuilt image needed.** Building from this Dockerfile in every CI run takes several minutes.
   Publish it (for example with a GitHub Actions `buildx` workflow) and pin by digest.
5. **ML-DSA private key format.** The fork's `ssh-keygen` format is not checked against the seed-only rule yet.
6. The server logs at `DEBUG3` (the maintainer finds this useful for diagnosing test failures).
7. Host key algorithms are limited to the ML-DSA names and `ssh-ed25519` in `sshd_config`.
   Adjust it for tests that need other types.

## CI: build and publish (`.github/workflows/oqs-openssh-image.yml`)

- Runs on `workflow_dispatch` (input: tag, default `dev`) and on pushes that touch this directory.
- Builds each architecture on a **native runner** (`ubuntu-24.04`, `ubuntu-24.04-arm`), so there is no QEMU emulation.
- Runs `smoke-test.sh` on each image. The test checks the algorithm lists and opens real sessions with
  pure ML-KEM, pure ML-DSA host keys and an ML-DSA user key.
- Pushes each image by digest to `ghcr.io/<owner>/mina-sshd-oqs-openssh`, then joins them into one multi-arch tag.
- To try it from a fork: push the branch, open the **Actions** tab, run **oqs-openssh-image**.
  Afterwards set the package to *public* in the GitHub package settings so that other machines can pull it.
- You can run the smoke test locally: `./smoke-test.sh <image> docker|podman`.

Actions are pinned by commit hash. The `docker/*` hashes are in the ASF allow-list
(`apache/infrastructure-actions`, `approved_patterns.yml`); `actions/*` are GitHub's own.
The image owner is taken from the repository owner (`ghcr.io/<owner>/...`). In `apache/mina-sshd`
that would be `ghcr.io/apache/...`. Whether the workflow may push there is not known; ASF Infra may
have to enable it.
