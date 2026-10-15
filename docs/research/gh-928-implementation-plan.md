# Implementation Plan: GH-928 – pure ML-KEM, ML-DSA and composite signatures

Based on: `docs/research/gh-928-pure-mldsa-mlkem.md`

**Revision 2.** Updated after the maintainer comment
https://github.com/apache/mina-sshd/issues/928#issuecomment-6180441945

## What changed (maintainer comment, summarised)

1. Contributions are welcome, even experimental. The maintainer is **wary of AI-generated code**. Every change needs careful human review and understanding.
2. **Pure ML-KEM is already done** by the maintainer (not pushed yet). We drop it from our plan.
3. The real blocker for KEX is **interoperability tests**. We need a Docker image with a reputable SSH implementation that supports pure ML-KEM. Without interop tests, releases would ship with the algorithms disabled.
4. **Composite `ssh-mldsa44-ed25519` comes first.** Stock OpenSSH can test it. Pure ML-DSA is then "a piece of cake" but also needs interop tests, and no usable container exists (none for wolfSSH; the oqs-openssh one is very old).
5. **Private keys must be stored as the seed only** in SSH format. This is compatible with `draft-ietf-sshm-composite-sigs` (Miller). The Fluhrer draft does not define it.
6. **Target the 3.0 stream (branch `dev_3.0`), not master.** Reasons:
   - 3.0 reworked security-provider handling;
   - 3.0 has multi-release JARs (MR-JARs), so the JDK built-in ML-DSA is used where available, and BouncyCastle (optional) otherwise;
   - code must use standard JCE interfaces;
   - merging from master into `dev_3.0` would be messy;
   - 3.0 uses Testcontainers 2.x and has moved container tests to a separate `sshd-test` project, run at the end of the build with all three I/O libraries (NIO2, MINA, Netty).
7. ML-DSA must be a **series of small PRs**: (a) keys and wire format, (b) OpenSSH file format read/write, (c) signature, (d) SSH certificates. Each with unit tests.

## Status (updated)

- All work is on branch `gh-928-pqc`, based on `upstream/dev_3.0`.
- Phase 0 study is done (see `gh-928-pure-mldsa-mlkem.md` §9). The issue reply is deferred.
- Phase 1 is in progress. The OQS-OpenSSH image is in `docker/oqs-openssh/`.
  The workflow `.github/workflows/oqs-openssh-image.yml` targets native amd64 and arm64 runners.
  The maintainer reviewed the image (add `DEBUG3`, pin ASF-approved actions: done).
- Local verification: `docker/oqs-openssh/smoke-test.sh ghcr.io/etnt/mina-sshd-oqs-openssh:dev docker`
  passed on arm64 (`ALL OK`, six pure ML-KEM/ML-DSA sessions). The runtime image is about 30 MB.
  `ssh -V` reports `OpenSSH_10.3-2026-05_p1, Open Quantum Safe 2026-05`.
  The Dockerfile comment and README now agree on the 10.3p1 base.
- The cached fork image index is
  `ghcr.io/etnt/mina-sshd-oqs-openssh@sha256:702c734e663283577e08b6f4f18910acb0b6cbf0a6fa36f9dd6a603124896a9b`.
  Its cached index contains amd64 and arm64 manifests. This does not prove that amd64 passes.
  The latest fork CI run and registry visibility were not checked in this local-only pass.
- Both Dockerfile stages now pin Alpine 3.22.6 by its cached multi-arch index digest
  `sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8`.
  Verified against the registry: it is an OCI image index with linux/amd64 and linux/arm64, and it is Alpine 3.22.6.
  The fork image above predates this explicit pin. Rebuild and run both architecture smoke tests before replacing the test image digest.
- Added `sshd-test/src/test/java/org/apache/sshd/client/kex/OqsOpenSshInteropTest.java`.
  The first test uses the existing `mlkem768x25519-sha256` hybrid and password authentication as `test`.
  The binary offers that hybrid, but the default `sshd_config` allows only pure ML-KEM.
  The test overrides KEX through sshd command-line options without changing the default configuration.
  A local stock OpenSSH 10.3p1 client negotiated that hybrid with an Ed25519 host key,
  authenticated with password `test` and received `CONNECTED_OK` from the pinned image.
  The session produced 12 server log lines with `LogLevel=VERBOSE`.
  A second test skips until a supported `mlkem768-sha256` factory lands. No pure ML-KEM implementation was added.
  Both tests require Ed25519 support and skip before image startup if their algorithms are unavailable.
  Image fetch failures, unknown hosts and explicit registry errors (such as `manifest unknown` or `pull access denied`) also skip the tests.
  Other launch failures, including startup timeouts and invalid sshd options, fail the tests.
- The Java test uses the pinned fork index, a two-minute startup timeout and a `Slf4jLogConsumer`.
  It overrides `DEBUG3` with `VERBOSE` to limit CI output. Image pull time is not measured because the image was cached.
  Use packaged multi-release JAR (MR-JAR) verification as the primary command, from the repository root:

  ```
  JAVA_HOME=/opt/homebrew/opt/openjdk ./mvnw -pl sshd-test -am -Pmultirelease -Dit.test=OqsOpenSshInteropTest -Dfailsafe.failIfNoSpecifiedTests=false verify
  ```

  Set `JAVA_HOME` to your local JDK 25 path. To select this class in Surefire too, add
  `-Dtest=OqsOpenSshInteropTest -Dsurefire.failIfNoSpecifiedTests=false`.
  Surefire runs NIO2, MINA and Netty by default. Failsafe uses the packaged JARs and runs NIO2 by default.
  Its reports are in `sshd-test/target/surefire-reports-mr/`, with the summary in `sshd-test/target/failsafe-reports/failsafe-summary.xml`.
- Packaged verification passed on arm64 with JDK 25.0.2 and Testcontainers 2.0.4 (`BUILD SUCCESS`, exit code 0).
  `docker info` succeeded through the local Podman 5.3.2 Docker-compatible server.
  Failsafe reported two tests: one hybrid pass, one pure ML-KEM skip, zero failures and zero errors.
  The hybrid negotiated `mlkem768x25519-sha256`, used an Ed25519 host key, authenticated with password `test`, and received `CONNECTED_OK`.
  The test asserts the negotiated KEX name. Testcontainers startup and the log-wait expression worked without changes.
  The exact pure-test skip reason was `Assumption failed: Enable after the maintainer's pure ML-KEM factory lands`.
  MINA has no `mlkem768-sha256` factory yet, so Java pure ML-KEM interoperability remains unverified.
  Surefire also passed the hybrid in each of NIO2, MINA and Netty, with one pure-test skip per execution.
  After narrowing image-error matching, the selected-class verification rerun passed with the same results and no flakes.
  The full run logged unrelated transient failures in `PortForwardingTest.localBindingOnDifferentInterfaces`, `ProxyJumpTest.proxyOverride` and `StrictKexInteroperabilityTest.strictKexOff`.
  All three passed on retry. Maven Enforcer and Apache RAT passed.
  The pinned image was cached. No image fetch failed, and no local rebuild or publication was needed.
  Fresh-pull access and registry visibility remain unchecked.
- Use the `test` phase only as a compile check, not as proof of interoperability:

  ```
  JAVA_HOME=/opt/homebrew/opt/openjdk ./mvnw -pl sshd-test -am -Dtest=OqsOpenSshInteropTest -Dsurefire.failIfNoSpecifiedTests=false test
  ```

  The earlier test-phase run compiled successfully but skipped both tests in all three I/O executions.
  The MR-JAR `JceKEM` implementation is active only in the packaged JAR.
  In the `test` phase, the SunJCE registrar claims ML-KEM support, but the baseline `JceKEM` stub throws.
  As a result, `BuiltinKEM.mlkem768` reports unsupported and the hybrid test skips before container startup.
  The pure ML-KEM test skips because its factory is absent.
- Deferred outside local scope: rebuild/publication, ASF Infra approval for `ghcr.io/apache`,
  maintainer confirmation of the connectivity-test scope and OQS source pin, and the issue #928 findings/Dockerfile post.
  No images were published and no external parties were contacted.
- OQS composite signatures cannot test `ssh-mldsa44-ed25519`. The separate OpenSSH 10.5 image remains open.
  Its release and package availability were not checked in this pass.
- Existing container tests in `sshd-test` build their image in code (`ImageFromDockerfile`, pinned
  Alpine plus `apk add`). Our image compiles C code, so tests must **pull the prebuilt image by
  digest** instead (`GenericContainer(DockerImageName.parse(...))`).
- Maintainer on private keys: PKCS#8 follows RFC 9881; SSH format stores the seed only. On input we
  may also accept "seed followed by expanded key" and ignore the expanded part.

## Guiding rules

- Experimental and opt-in. Not in defaults.
- Standard JCE interfaces for ML-DSA. No BouncyCastle-specific types in the API. BC stays optional.
- Java 8 baseline is kept for the KEM (BC low-level API). ML-DSA uses MR-JAR on newer Java.
- Private keys are stored as the **seed only**.
- Small, reviewable PRs. We read, understand and test every line before submitting. Disclose AI assistance if the project asks for it.
- Work on `dev_3.0`. Do not start code on master.

## Phase 0 – Environment and alignment (about 2–3 days)

1. Reply on the issue: thank the maintainer, accept the 3.0 target, the seed-only private key rule and the PR series. Offer help with interop tests (see Phase 1). State how we will handle AI-assisted code (human-written and reviewed; we can disclose).
2. Check out `dev_3.0`. Study the 3.0 changes: security provider registrars, MR-JAR layout, `sshd-test` project, Testcontainers 2.x setup.
3. Read the exact specs: `draft-ietf-sshm-composite-sigs` (key and signature layout, seed storage, combiner), the Fluhrer pure ML-DSA draft, FIPS 204.
4. Check the JDK built-in ML-DSA (JDK 24+: `KeyPairGenerator`/`Signature` `ML-DSA-44` and `KeyFactory`; seed import via PKCS#8) and BC's JCE names. Confirm what seed-only import and export look like in both.
5. Update the research document with the corrected assumptions.

Exit: the maintainer agrees with the order; we know the JCE API surface we can use on both providers.

## Phase 1 – Interop test infrastructure (about 3–5 days, parallel with Phase 2)

This is the main blocker the maintainer named, and it is the most useful contribution we can make that does not clash with his own work.

1. Survey candidate third-party implementations for a **pure ML-KEM** server/client: OpenSSH (check the release that ships pure `mlkem768`, if any), libssh, wolfSSH, Dropbear, AsyncSSH, Go `x/crypto/ssh`, Paramiko/others. Prefer reputable projects.
2. For each: does it support pure ML-KEM and pure/composite ML-DSA? Is there a maintained container image, or can we build one from a pinned release?
3. Build a container image (Dockerfile in `docker/oqs-openssh/` on `dev_3.0`) for the best candidate. Pin versions and the Alpine multi-arch index. Tests in `sshd-test` pull the prebuilt image by digest through `GenericContainer`. Verify it runs with Testcontainers 2.x.
4. Prove it manually: connect with a stock client and check the negotiated algorithms in verbose output.
5. Share the findings on the issue. Offer the Dockerfile or a PR.
6. Also check: OpenSSH 10.5 container for `ssh-mldsa44-ed25519` (needed in Phase 4).

Exit: at least one working, pinned container for pure ML-KEM, and one for the composite ML-DSA key type (OpenSSH 10.5). The result for pure ML-DSA is documented, even if negative.

## Phase 2 – ML-DSA keys and wire format (PR 1, about 1 week)

Scope: key types and buffer encoding only. No files, no signatures.

1. Provider layer: `SecurityUtils`/registrar support check for ML-DSA, using JCE (`KeyFactory`, `KeyPairGenerator`) with the MR-JAR approach from 3.0.
2. Key type constants and a parameter table (`ML-DSA-44/65/87`: name, public key size, seed size 32 bytes).
3. Public key: `PublicKeyEntryDecoder`, and `BufferPublicKeyParser` (read and write `string name; string key`). Register in `KeyUtils`.
4. Private key object model: seed-only. Derive the expanded key through the provider.
5. Unit tests: encode/decode round trip, size checks, bad input rejected, known-answer values from FIPS 204/ACVP, with BC and with the JDK provider where available.

Exit: public keys round-trip through `Buffer`; tests pass on both providers.

## Phase 3 – OpenSSH key file format (PR 2, about 3–5 days)

1. Private key decoder/encoder for OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`), **seed only**, compatible with the composite draft. Model on the Ed25519 decoder.
2. `authorized_keys` / `known_hosts` / `.pub` read and write for the new key types.
3. Fingerprints and `KeyRandomArt`.
4. Key generation in `SimpleGeneratorHostKeyProvider`/`AbstractGeneratorHostKeyProvider`.
5. Tests: read keys produced by `ssh-keygen` of OpenSSH 10.5 (stored as test resources); write keys and read them back with `ssh-keygen -y` (in a container if needed).

Exit: keys generated by OpenSSH 10.5 load in MINA, and ours load in OpenSSH.

## Phase 4 – Composite `ssh-mldsa44-ed25519` signature (PR 3, about 1 week)

1. `Signature` class following `draft-ietf-sshm-composite-sigs` exactly (combiner, domain label, prehash). Both parts must verify.
2. Design decision before coding: the JDK SUN provider rejects a non-empty ML-DSA context (research §9.5), so the composite scheme cannot use SUN alone. Either require Bouncy Castle for the composite, or use our own ML-DSA component path. Also, SUN on JDK 24/25 rejects seed-only PKCS#8 keys, so seed import needs BC or an RFC 9881 workaround.
3. Register in `BuiltinSignatures` and `BuiltinIdentities` (`isSupported()` needs ML-DSA and Ed25519). Not in defaults.
4. Tests: unit sign/verify, tamper tests (each part), session test between our client and server.
5. Interop tests (in `sshd-test`, all three I/O libraries): our client against OpenSSH 10.5 container with host key and user key authentication, and the reverse where practical.

Exit: interoperability with stock OpenSSH 10.5 proven in CI.

## Phase 5 – Pure ML-DSA signatures (PR 4, about 3–5 days)

1. Add `ssh-mldsa-44/65/87` using the Phase 2–4 code. Names and encodings as in the Fluhrer draft; private keys are seed only.
2. Register in `BuiltinSignatures`. Not in defaults.
3. Interop: only if Phase 1 found a usable container. If not, ship with the algorithm disabled by default and documented as not interop-tested, as the maintainer described. Keep checking for a container.
4. Policy test: a pure-PQC-only configuration (pure ML-KEM from the maintainer's work plus pure ML-DSA).

## Phase 6 – SSH certificates (PR 5, about 3–5 days)

1. Check whether the drafts define certificate types for ML-DSA (`...-cert-v01@openssh.com`) and what OpenSSH does.
2. Extend `OpenSshCertificate` handling for the new key types where needed.
3. Tests with certificates signed by OpenSSH 10.5 `ssh-keygen -s`.

## Phase 7 – Hardening, docs, release (about 2–3 days)

1. Large keys and signatures vs. packet size and parsers.
2. Build with and without BC; run on the oldest and newest supported Java (MR-JAR paths).
3. Update `docs/standards.md`, security-provider docs, change notes. Mark as experimental.
4. Re-check names and encodings when the drafts move or become RFCs.

## Order and dependencies

```
Phase 0 ──> Phase 1 (interop containers) ───────────────┐
        └─> Phase 2 ──> Phase 3 ──> Phase 4 ──> Phase 5 ──> Phase 6 ──> Phase 7
                                        ▲
                       needs Phase 1 (OpenSSH 10.5 image)
```

Pure ML-KEM: owned by the maintainer. We contribute only the interop container and test review (Phase 1).

## Estimated total

About 4–5 weeks for one developer. The elapsed time depends on review speed and on whether a pure ML-DSA test container exists.

## Risks

| Risk | Effect | Mitigation |
|---|---|---|
| No third-party container with pure ML-KEM/ML-DSA | Algorithms ship disabled | Phase 1 survey; build our own image from a reputable implementation; keep looking |
| AI-generated code rejected | PRs stall | Small PRs, human-written and fully understood; follow the maintainer's review comments |
| `dev_3.0` internals differ from master | Wrong designs | Phase 0 study before coding |
| JDK and BC differ on seed import/export | Seed-only keys break | Phase 0 check; test both providers in Phase 2 |
| SUN rejects non-empty ML-DSA context and, on JDK 24/25, seed-only PKCS#8 keys | Composite signature and seed-only keys fail on the JDK provider | Decide in Phase 4: require BC for the composite, or own component path; see research §9.5 |
| Draft changes | Rework | Keep names and layouts in one place; experimental label |
| Pure ML-DSA private key format is unspecified in the Fluhrer draft | Incompatibility | Follow the composite draft (seed only) |
