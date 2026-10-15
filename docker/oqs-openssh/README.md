<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# OQS-OpenSSH test container (pure ML-KEM and pure ML-DSA)

Interoperability test server for GH-928. It runs the Open Quantum Safe fork of OpenSSH
(branch `OQS-v10`, OpenSSH 10.3p1 based) on Alpine 3.22.6.
The local image reports `OpenSSH_10.3-2026-05_p1, Open Quantum Safe 2026-05` from `ssh -V`.
Both Dockerfile stages pin the Alpine multi-arch index by digest.
Verified against the Docker Hub registry: `sha256:5291449c…` is an OCI image index that lists
`linux/amd64` and `linux/arm64` (v8), and the image reports Alpine 3.22.6 in `/etc/alpine-release`.

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
| Multi-arch (x86_64 and arm64) | The cached image index contains both architectures. The local smoke test passed on arm64. The amd64 CI result is not verified locally. |
| No compile or heavy base at test time | Compilation happens once in the image build. Tests must pull a **prebuilt, published** image. |

## Checked on arm64 (podman)

- `ssh -Q kex` in the container lists `mlkem768-sha256` and the other pure names.
- `ssh -Q key` lists `ssh-mldsa-44/65/87`.
- A connection with `KexAlgorithms=mlkem768-sha256`, `HostKeyAlgorithms=ssh-mldsa-65` and a
  `ssh-mldsa-44` user key authenticated and ran a command.

## Pinned image and Java tests

The locally cached fork image has this multi-arch index reference:

```
ghcr.io/etnt/mina-sshd-oqs-openssh@sha256:702c734e663283577e08b6f4f18910acb0b6cbf0a6fa36f9dd6a603124896a9b
```

The cached index contains `linux/amd64` and `linux/arm64`. Only arm64 was smoke-tested locally.
The Java tests used the cached arm64 image. They did not check a fresh pull, package visibility or the latest CI run.
The image predates the explicit Alpine digest pin in the Dockerfile. No image was rebuilt or published in this pass.

`sshd-test/src/test/java/org/apache/sshd/client/kex/OqsOpenSshInteropTest.java` pulls this image through
`GenericContainer`. It does not build the Dockerfile at test time.
The connectivity test selects `mlkem768x25519-sha256` and an Ed25519 host key, then authenticates with password `test`.
The image binary supports this hybrid, but the default server configuration permits only pure ML-KEM.
The test uses sshd command-line options to select the hybrid without changing the image configuration.
A local stock OpenSSH 10.3p1 client passed this hybrid/Ed25519/password session against the pinned image and received `CONNECTED_OK`.
The pure `mlkem768-sha256` test skips until MINA provides a supported factory with that name.
Both tests skip before image startup if the required algorithms are unavailable.
Image fetch failures, unknown hosts and explicit registry errors (such as `manifest unknown` or `pull access denied`) also skip the tests.
Other launch failures, including startup timeouts and invalid sshd options, fail the tests.

The test allows two minutes for startup, after the image pull.
For slow registries, set Testcontainers' `pull.timeout` in `~/.testcontainers.properties` (for example, `pull.timeout=300`).
The pull time was not measured because the image was already cached.
The test overrides `DEBUG3` with `VERBOSE` to limit logs. The local stock-client session produced 12 server log lines.
The image keeps `DEBUG3` as its default.
Surefire redirects test output to the per-I/O report directories.

From the repository root, run the packaged multi-release JAR (MR-JAR) verification with JDK 25:

```
JAVA_HOME=/opt/homebrew/opt/openjdk ./mvnw -pl sshd-test -am -Pmultirelease -Dit.test=OqsOpenSshInteropTest -Dfailsafe.failIfNoSpecifiedTests=false verify
```

Set `JAVA_HOME` to your local JDK 25 path. Failsafe uses the packaged JARs, which activate the JDK-specific `JceKEM` implementation.
The command also runs the default Surefire tests with NIO2, MINA and Netty.
To select only this class in Surefire too, add `-Dtest=OqsOpenSshInteropTest -Dsurefire.failIfNoSpecifiedTests=false`.
Failsafe writes its test reports to `sshd-test/target/surefire-reports-mr/` and its summary to `sshd-test/target/failsafe-reports/failsafe-summary.xml`.
The default Failsafe execution uses NIO2, not all three I/O libraries.

Local verification on arm64 used JDK 25.0.2 and Testcontainers 2.0.4.
`docker info` succeeded through the local Podman 5.3.2 Docker-compatible server.
The command above finished with `BUILD SUCCESS` (exit code 0).
Failsafe reported two tests: the hybrid passed, the pure ML-KEM test skipped, and neither failed.
The hybrid negotiated `mlkem768x25519-sha256`, authenticated with an Ed25519 host key and password `test`, and received `CONNECTED_OK`.
The test asserts the negotiated KEX name. Container startup and the log-wait expression worked without changes.
The exact pure-test skip reason was `Assumption failed: Enable after the maintainer's pure ML-KEM factory lands`.
MINA has no `mlkem768-sha256` factory yet, so Java pure ML-KEM interoperability remains unverified.
Surefire also passed the hybrid in NIO2, MINA and Netty, with one pure-test skip per execution.
After narrowing the image-error checks, the selected-class verification command also passed with the same results.
The full run logged unrelated transient failures in `PortForwardingTest.localBindingOnDifferentInterfaces`, `ProxyJumpTest.proxyOverride` and `StrictKexInteroperabilityTest.strictKexOff`.
All three passed on retry.
The selected-class rerun had no flakes. Maven Enforcer and Apache RAT passed.
The cached image avoided a pull, so this does not prove registry access. No local rebuild was needed.

Use the `test` phase only as a compile check, not as proof of Java interoperability:

```
JAVA_HOME=/opt/homebrew/opt/openjdk ./mvnw -pl sshd-test -am -Dtest=OqsOpenSshInteropTest -Dsurefire.failIfNoSpecifiedTests=false test
```

The earlier test-phase run compiled successfully but skipped both tests in each I/O execution.
The MR-JAR `JceKEM` implementation is active only in the packaged JAR.
In the `test` phase, the SunJCE registrar claims ML-KEM support, but the baseline `JceKEM` stub throws.
As a result, `BuiltinKEM.mlkem768` reports unsupported and the hybrid test skips before container startup.
The pure ML-KEM test skips because its factory is absent.

To update the pin after an authorized publication:

1. Make sure that both native architecture jobs pass `smoke-test.sh` for the new image.
2. Run `docker buildx imagetools inspect ghcr.io/<owner>/mina-sshd-oqs-openssh:<tag>`.
3. Copy the top-level index digest, not an architecture-specific manifest digest.
4. Replace `OQS_OPENSSH_IMAGE` in the Java test and the reference above.
5. Run the Java test in all three I/O modes, including a fresh image pull.

Publication under `ghcr.io/apache/mina-sshd-oqs-openssh` still needs ASF Infra approval.
When it is available, change the single image constant to the ASF image and its verified index digest.
No registry-name change is needed in the workflow: it already uses the repository owner.

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
4. **ASF image still needed.** The Java test pins the cached fork image by index digest.
   The updated Dockerfile still needs a rebuild, smoke tests on both architectures and authorized publication.
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
