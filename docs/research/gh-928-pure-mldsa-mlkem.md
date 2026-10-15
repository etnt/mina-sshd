# Research: GH-928 – pure ML-DSA signatures and pure ML-KEM key exchanges

Issue: https://github.com/apache/mina-sshd/issues/928 (open, no assignee)

Phase 0 findings, recorded on 2026-10-15, are in [section 9](#9-phase-0-findings-2026-10-15).
Sections 1–8 preserve the initial research and its untested assumptions. Section 9 supersedes them where they conflict.
The work order remains in [the implementation plan](gh-928-implementation-plan.md), not in the historical section 7 below.

## 1. Summary of the issue

The reporter asks for:

- **Pure ML-DSA** host/user key signatures – `draft-sfluhrer-ssh-mldsa`.
- **Pure ML-KEM** key exchange (no X25519/NIST-curve hybrid) – `draft-harrison-sshm-mlkem`.

Motivation: US CNSA 2.0 (`draft-becker-cnsa2-ssh-profile`) requires pure PQC for procurement from about 2027. Existing implementations: wolfSSH and oqs-openssh (ML-DSA); oqs-openssh and CycloneSSH (ML-KEM). Issue GH-915 also mentions ML-DSA.

Maintainer response (tomaswolf):

- Both drafts are **not adopted** by the IETF SSHM WG. Discussion is still active.
- IANA names are already reserved for both drafts.
- The WG goes first with **composite** signatures. OpenSSH 10.5 shipped `ssh-mldsa44-ed25519`. Implementing that would also give interoperability tests.

Reporter follow-up: would a contribution, even if experimental, be reviewed and merged? There is no answer yet.

**Conclusion:** Technically this is a moderate change. The ML-KEM part is small. The ML-DSA part is larger. The main risk is wire-format instability while the drafts are unadopted. Plan for an opt-in, experimental feature. Agree with the maintainers before coding.

## 2. Current state of the code base

### Key exchange
- `sshd-core/.../common/kex/KeyEncapsulationMethod.java` – generic KEM client/server interface.
- `MLKEM.java` – Bouncy Castle (BC) wrapper. Supports `mlkem768` and `mlkem1024`. It loads BC classes lazily and reports `isSupported()`.
- `BuiltinKEM.java` – enum: `mlkem768`, `mlkem1024`, `sntrup761`.
- `BuiltinDHFactories.java` – registers the hybrids `mlkem768x25519-sha256`, `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384` and the sntrup761 ones. Hybrids use `XDH` or `ECDH` with `getKeyEncapsulation()` and `getHash()`.
- `BaseBuilder.java` (~line 90) – default KEX list.
- `AbstractDH`, `XDH`, `ECDH` – hybrid key-agreement logic. K is derived from the KEM secret combined with the ECDH secret.
- Tests: `OpenSshMlKemTest`.
- Docs: `docs/standards.md` (line ~103), `docs/changes/2.15.0.md`.

### Signatures / keys
- `sshd-common/.../common/signature/BuiltinSignatures.java` – enum of signature factories (`ed25519`, `ed25519_cert`, `sk_ssh_ed25519`, ...).
- `KeyPairProvider` – key type name constants (`SSH_ED25519`, ...).
- Key-type pieces to copy for a new type (Ed25519 as model, under `common/util/security/eddsa/`):
  - public key decoder (`PublicKeyEntryDecoder`);
  - OpenSSH private key decoder (`PrivateKeyEntryDecoder`);
  - buffer public key parser (`util/buffer/keys/ED25519BufferPublicKeyParser`);
  - `Signature` implementation (`AbstractSignature`);
  - PEM/PKCS#8 parser (`...PEMResourceKeyParser`);
  - registration through `SecurityUtils` and a `SecurityProviderRegistrar`.
- No ML-DSA code exists today.
- Java baseline is **8** (`java.sdk.version`). BC is 1.86 (optional dependency). JDK 24+ has native ML-DSA/ML-KEM, but it cannot be used at compile time with a Java 8 release.

## 3. Part A – pure ML-KEM key exchange (small)

Wire format (to verify against the current draft text):

- Names: `mlkem768-sha256`, `mlkem1024-sha384`. Names may change before adoption.
- Client sends `C_INIT` with the ML-KEM public key. Server replies with the ciphertext and the host key signature.
- Exchange hash is computed with the named hash. K_PQ is encoded as an **mpint** (draft-harrison-sshm-mlkem, section 3.1; verified).

Implementation steps:

1. Add `mlkem768` / `mlkem1024` constants to `BuiltinDHFactories.Constants`, and enum entries.
2. Add a new class, e.g. `KemKeyExchange` (extends `AbstractDH`, or `AbstractDHKeyExchange` if the existing wiring fits). It does only the KEM:
   - `calculateE()` returns `kem.getClient().getPublicKey()`;
   - `calculateK()` returns the secret extracted from `f`.
   - Server side uses `KeyEncapsulationMethod.Server.init(pk)` and returns the encapsulation as `f`.
   - Reuse `MLKEM` and `BuiltinKEM` unchanged.
3. Check how `DHGClient`/`DHGServer` treat `K` for the hybrid case (string vs mpint, `raw` flag in `XDH`). Copy the hybrid behaviour. Check that the server rejects a public key of the wrong length (`Server.init` currently allows trailing bytes; pure KEM must require an exact length).
4. `isSupported()` = `BuiltinKEM.mlkemXXX.isSupported()` and the digest is supported.
5. **Do not add to `BaseBuilder` defaults.** Users enable it explicitly. This is safer while the drafts are not final.
6. Tests: a client/server round trip in `sshd-core` (follow `OpenSshMlKemTest`); a negative test for wrong lengths; an interop test against oqs-openssh if a Docker image is available (the repo has Testcontainers-based ITs in `sshd-git`/`sshd-sftp`; check for existing OpenSSH container tests).
7. Docs: `docs/standards.md`, a new `docs/changes/` entry, and a note on the experimental status.

Effort: about 1–2 days including tests.

## 4. Part B – ML-DSA signatures (medium)

Wire format (to verify against the draft text):

- Key type names: `ssh-mldsa-44`, `ssh-mldsa-65`, `ssh-mldsa-87` (`ML-DSA-44/65/87`, FIPS 204).
- Public key blob: `string name; string raw-public-key` (1312 / 1952 / 2592 bytes).
- Signature blob: `string name; string raw-signature` (2420 / 3309 / 4627 bytes). "Pure" ML-DSA, with empty context.
- OpenSSH private key format: need the layout used by oqs-openssh/wolfSSH. The private key is probably the 32-byte seed or the expanded key. This is **not yet standardised**.

Implementation steps:

1. **Provider.** Use BC (`org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator`, `org.bouncycastle.crypto.signers.MLDSASigner`, `MLDSAParameters.ml_dsa_44/65/87`) or the JCA names `ML-DSA-44/65/87` from the BC provider. The JCA route fits MINA's `KeyPair`/`PublicKey` model better, and it makes JDK 24+ usable at run time without code changes. Keep BC classes out of signatures so loading stays lazy (see how `MLKEM.Parameters` hides them behind `Object`).
2. **Key type constants** in `KeyPairProvider` and in a new `MlDsaKeyType` helper.
3. **Public key decoder** `MlDsaPublicKeyEntryDecoder` (modelled on `GenericEd25519PublicKeyDecoder`), plus the `BufferPublicKeyParser` for `Buffer.getRawPublicKey()`. Register in `KeyUtils`/`PublicKeyEntry` decoder lists.
4. **Private key decoder** for OpenSSH format (`GenericOpenSSHEd25519PrivateKeyEntryDecoder` as model) and optionally PKCS#8 (BC supports ML-DSA PKCS#8 per RFC 9881 draft).
5. **Signature class** `SignatureMlDsa` (extends `AbstractSignature`): `sign` = `string(name) string(sig)`, `verify` using `extractEncodedSignature`.
6. **Register** in `BuiltinSignatures` (three entries, `isSupported()` via a `SecurityUtils.isMlDsaSupported()` check), `SecurityUtils`, and `BuiltinIdentities`.
7. **Key generation:** `SimpleGeneratorHostKeyProvider`/`AbstractGeneratorHostKeyProvider`, `KeyUtils.getPublicKeyEntryDecoder`, key fingerprint, `KeyRandomArt`.
8. **Defaults:** not in the default signature list. Add only to explicit configuration.
9. **Tests:** unit tests for encode/decode, sign/verify, known-answer vectors (NIST ACVP or the draft's test vectors); an end-to-end session test with ML-DSA host key and user key; interop with oqs-openssh or wolfSSH.
10. **Cost notes:** key and signature sizes are large. Check limits for packet size and for the `authorized_keys` line length parser. Buffer limits for host key blobs (`Buffer`/`SessionContext` max packet size 256 KiB by default) are fine.

Effort: about 1–2 weeks including interop.

## 5. Part C – composite `ssh-mldsa44-ed25519` (what the maintainers prefer)

- Already shipped in OpenSSH 10.5, which gives real interop tests.
- Composite signature = ML-DSA-44 + Ed25519 both verified. Needs the draft-defined combiner (prehash, domain separation label). It reuses Part B's key and signature machinery plus the existing Ed25519 support.
- Same registration steps as Part B. Do this first or together with B; B then only adds the pure variants.
- Tracks `draft-*-sshm-*` composite drafts. Read the exact draft to get the combiner and the key and signature layout.

## 6. Risks and open questions

| Topic | Notes |
|---|---|
| Draft stability | Neither draft is WG-adopted. Names are reserved, but encoding may change. Mitigate: experimental flag, not in defaults, document it. |
| Maintainer acceptance | Not confirmed. Ask on the issue; propose small separate PRs (ML-KEM first). |
| BC dependency | ML-DSA APIs are in BC ≥ 1.79. The project uses 1.86, so it is available. BC stays optional. |
| JDK native support | JDK 24+ has ML-DSA/ML-KEM, but the build targets Java 8. Use JCA names reflectively, or use the BC provider only. |
| Private key format | No standard for OpenSSH-format ML-DSA private keys. Align with OpenSSH 10.5 / oqs-openssh. |
| Test vectors | Use FIPS 203/204 ACVP vectors from BC and the draft's examples. |
| Security policy | CNSA 2.0 may forbid fallbacks. Users must be able to configure a pure-PQC-only KEX and signature list. This already works through the factory lists. |
| FIPS | Pure ML-KEM must reject hybrids if configured so; no code change needed. |

## 7. Suggested plan

1. Comment on the issue: propose experimental, opt-in support, ask for the maintainers' agreement on scope and order.
2. PR 1 – pure ML-KEM KEX (`mlkem768-sha256`, `mlkem1024-sha384`), small and low risk.
3. PR 2 – ML-DSA key type infrastructure and the composite `ssh-mldsa44-ed25519` (interop with OpenSSH 10.5).
4. PR 3 – pure `ssh-mldsa-44/65/87`.
5. Update `docs/standards.md`, changelog; revisit defaults when drafts are adopted as RFCs.

## 8. References

- https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/
- https://datatracker.ietf.org/doc/draft-harrison-sshm-mlkem/
- https://datatracker.ietf.org/doc/draft-becker-cnsa2-ssh-profile/
- https://datatracker.ietf.org/wg/sshm/documents/
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
- Related: GH-606 (hybrid ML-KEM, done in 2.15.0), GH-915

> Historical caveat: sections 1–8 used draft details from memory and did not inspect the BC jar. The Phase 0 findings below replace those assumptions.

## 9. Phase 0 findings (2026-10-15)

This is a research result, not an implementation proposal. No library code, defaults, container tests, or build configuration changed.
The provider and specification study is complete. The assumptions about JDK seed import and composite signature support are not correct for all JDKs.
The issue reply and acceptance of these newly discovered limits remain open.

### 9.1 Checkout, environment, and maintainer alignment

The checkout is `gh-928-pqc` at `82f2401b5`, based on `upstream/dev_3.0` at `e51bd4725`.
`git merge-base --is-ancestor upstream/dev_3.0 HEAD` returned 0. This is the requested 3.0 code, not master.
The existing branch was retained. Switching branches was unnecessary and risks disturbing the current work.

The shell uses Homebrew OpenJDK 21.0.10 on macOS arm64. Maven 3.9.9 uses Homebrew OpenJDK 25.0.2 instead.
The current root `pom.xml` requires JDK 24 or later and Maven 3.9.12 or later for builds.
Its `java.sdk.version` and `maven.compiler.release` retain Java 8 for baseline classes.
The milestone notes still name Maven 3.9.11. The current POM is the authority for this checkout.
No Maven build or repository test suite ran. The installed Maven is below the required version.
The repository wrapper selects Maven 3.9.16, so `./mvnw` with JDK 24+ is an available build route.
Standalone provider probes ran on JDK 21.0.10, OpenJDK 24.0.2, OpenJDK 25.0.2, and OpenJDK 27.
The latter three distributions and BC 1.86 were downloaded to a temporary directory outside the repository.

The issue comments were read through the public GitHub API. The maintainer explicitly accepts ML-DSA PRs against `dev_3.0`, time permitting.
The agreed order is keys and buffers, OpenSSH files, signatures, then certificates, each with unit tests.
Composite `ssh-mldsa44-ed25519` comes before pure ML-DSA. Pure ML-KEM belongs to the maintainer.
The [follow-up comment](https://github.com/apache/mina-sshd/issues/928#issuecomment-6190939136) distinguishes RFC 9881 PKCS#8 from seed-only SSH storage.
It permits consideration of SSH input containing a seed followed by an expanded key. It does not require writing that form.

No issue comment was posted by this research task. An account owner must approve and send the alignment reply.
The reply needs to thank the maintainer, accept 3.0, seed-only SSH storage, and the PR series, and offer help with interoperability tests.
It must disclose the actual AI assistance and require human understanding and review of every submitted line.
This research and its probes are AI-assisted. Describing them as human-written is not accurate.
The existing maintainer comments establish the preferred order, but do not approve the provider limits found below.
Thus the full Phase 0 exit condition is not yet met.

### 9.2 Provider path under sshd-common

All paths in this subsection are under `sshd-common/src/main/java/org/apache/sshd/common/util/security/` unless stated otherwise.
A registrar selects a security provider for an algorithm.
The study started with these classes, then followed their factory and version-specific paths:

| File or method | Observed behavior in 3.0 |
|---|---|
| `SecurityUtils.DEFAULT_SECURITY_PROVIDER_REGISTRARS` | Ordered as SunJCE wrapper, SunEC wrapper, net.i2p EdDSA, then BC. |
| `SecurityUtils.register()` | Performs automatic registration once. Explicit registration and configuration affect selection. |
| `SecurityUtils.resolveSecurityEntityFactory()` | Caches the selected factory by entity class and case-insensitive algorithm name. |
| `SecurityUtils.createSecurityEntityFactory()` | Selects the first enabled, supported registrar that claims the entity. With no match, uses the configured default or JCA lookup. |
| `SecurityEntityFactory` | Offers `Default`, `Named`, and `ByProvider` implementations. They call standard JCA/JCE factories. |
| `SecurityUtils.getKeyFactory()`, `getKeyPairGenerator()`, `getSignature()` | Already return standard `KeyFactory`, `KeyPairGenerator`, and `Signature`. No new low-level signing interface is needed. |
| `SecurityProviderRegistrar` and `AbstractSecurityProviderRegistrar` | Handle provider names or instances, per-entity configuration, enablement, and cached support declarations. |
| `SunJCESecurityProviderRegistrar` | Prefers SunJCE AES and SHA MACs. Advertises ML-KEM-768/1024 and their factories when available. Does not advertise ML-DSA. |
| `SunECSecurityProviderRegistrar` | Prefers SunEC Ed25519, X25519, and X448 when available. Does not advertise ML-DSA. |
| `bouncycastle/BouncyCastleSecurityProviderRegistrar` | Defaults to claiming all entities, with special checks for Ed25519 and KEM. It has no ML-DSA capability check. |
| `bouncycastle/BouncyCastleAccessor` | Defers ordinary BC references through a nested `Inner` class. Uses reflection for BC-FIPS and isolates failures when BC is absent. |

There is no built-in `SUN` wrapper for ML-DSA. OpenJDK ML-DSA belongs to `SUN`, not `SunEC` or `SunJCE`.
Therefore, the current registrar order does not prefer JDK ML-DSA over BC when BC claims the algorithm.
Without a matching registrar, default JCA lookup can find `SUN` on suitable JDKs.
A selected registrar that cannot create an algorithm does not automatically fall through to the next registrar.
A BC support declaration is not proof that an older BC or BC-FIPS installation implements ML-DSA.

The configuration uses `org.apache.sshd.security.registrars` and `org.apache.sshd.security.provider.<registrar>.<entity>`.
For example, `org.apache.sshd.security.provider.BC.enabled=false` disables that registrar.
Because selection is cached, provider configuration must precede use.
Key generation, parsing, and signatures need compatible provider choices. Mixed provider key objects are not universally interchangeable.
Encoded key specifications provide a standard conversion boundary, subject to the format differences below.

BC dependencies remain optional in `sshd-common/pom.xml`. The root POM pins ordinary BC to 1.86.
The accessor pattern, not new reflection over JCA factory methods, is the relevant model for optional provider-specific helpers.
The existing FIPS mode disables the Sun wrappers and Ed25519 and selects BC-FIPS rather than ordinary BC.
These probes did not test BC-FIPS or establish FIPS 140 validation.

### 9.3 Multi-release JAR and container-test layout

A multi-release JAR (MR-JAR) contains alternative classes for newer runtimes.
`sshd-common/pom.xml` compiles the following source sets:

| Source directory | Class release and packaged location | Existing purpose |
|---|---|---|
| `sshd-common/src/main/java` | Java 8, JAR root | Baseline classes and provider-independent interfaces. |
| `sshd-common/src/main/java11` | Java 11, `META-INF/versions/11` | ChaCha20 factory and Poly1305 implementation. |
| `sshd-common/src/main/java15` | Java 15, `META-INF/versions/15` | JCE Ed25519 public-key recovery and key-type detection. |
| `sshd-common/src/main/java24` | Java 24, `META-INF/versions/24` | `JceKEM` backed by `javax.crypto.KEM`. |

The `compile-11`, `compile-15`, and `compile-24` executions use `multiReleaseOutput=true` and their respective `release` values.
Replacement classes retain the same package and class name as their baseline versions.
For example, baseline `JceKEM` reports no support, while the Java 24 class wraps JCE encapsulation and decapsulation.
Baseline `eddsa/jce/JcePublicKeyFactory` returns null. Its Java 15 replacement uses newer EdEC interfaces.
Runtime class selection uses the highest applicable version in the packaged MR-JAR.
Using only `target/classes` as the classpath does not exercise that selection.

`sshd-osgi/pom.xml` unpacks the component JARs into its bundle, including versioned class entries.
Both `sshd-common` and `sshd-osgi` are documented MR-JAR artifacts in `docs/changes/3.0.0-M2.md`.
This study inspected source and POM layout, not a newly built artifact or manifest.
In `sshd-common`, Surefire runs baseline/default and BC configurations.
Failsafe runs the packaged-JAR `jce` execution with the BC and net.i2p registrars disabled.
A build stopped at `test` does not run that packaged-JAR check.

The final reactor module is `sshd-test`. The root POM imports Testcontainers BOM 2.0.4.
`sshd-test/pom.xml` uses `testcontainers` and `testcontainers-junit-jupiter` as test dependencies.
Surefire runs NIO2 by default, plus MINA and Netty executions through the active-by-default property-based profiles.
Those profiles are disabled by `test.mina=disable` and `test.netty=disable` respectively.
The JDK 11+ `multirelease` profile adds a packaged-JAR Failsafe run using NIO2.

`sshd-test/src/test/java/org/apache/sshd/client/kex/OpenSshMlKemTest.java` builds a pinned Alpine image with `ImageFromDockerfile`.
It installs OpenSSH with `apk` and captures logs through `Slf4jLogConsumer`.
`sshd-test/src/test/java/org/apache/sshd/AbstractContainerTestBase.java` adds a build discriminator to avoid cross-execution image-cache failures.
The branch already contains `docker/oqs-openssh/` and its publishing workflow. No image was built or test added during Phase 0.
The plan's prebuilt-image-by-digest requirement still applies to that C build. The existing Alpine test is not its integration.

### 9.4 Specifications read and exact formats

The versions below were retrieved on 2026-10-15. Datatracker reported composite revision 00 and pure revision 08.
These are pinned research references, not claims that later revisions will preserve the same bytes.

| Source | Sections used |
|---|---|
| [draft-ietf-sshm-composite-sigs-00](https://www.ietf.org/archive/id/draft-ietf-sshm-composite-sigs-00.txt), 2026-08-21 | 4.1 key generation and encoding, 4.2 contexts and signatures, 5 key separation. |
| [draft-ietf-lamps-pq-composite-sigs-19](https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.txt), referenced by composite-00 | 3.1, 3.2, verification, and the MLDSA44/Ed25519 label. |
| [draft-sfluhrer-ssh-mldsa-08](https://www.ietf.org/archive/id/draft-sfluhrer-ssh-mldsa-08.txt), 2026-08-28 | 3–8 names, keys, signatures, and length checks. |
| [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf), August 2024 | 3.6.2 length checks, 3.6.3 seed retention, 4 sizes, 5 external functions, 6.1 seed expansion, 7.2 encodings. |
| [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) | 2 identifiers, 4 public keys, 6 private key choices, 8 seed retention and consistency. |
| [IANA SSH registry](https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml) | Lists `ssh-mldsa-44/65/87` and the two composite names. Registration is not an interoperability test. |

FIPS 204 uses a 32-byte key-generation seed for every parameter set.
The seed is not the expanded secret key and cannot be recovered from an expanded key after it is discarded.
The standard explicitly permits seed retention, with the protections of a private key.

| Parameter set | Raw public key | Expanded private key | Raw signature | Seed |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 1312 | 2560 | 2420 | 32 |
| ML-DSA-65 | 1952 | 4032 | 3309 | 32 |
| ML-DSA-87 | 2592 | 4896 | 4627 | 32 |

All lengths in this section are bytes. FIPS 204 requires exact public-key and signature lengths.
ML-DSA accepts a context of at most 255 bytes. Its pure signing operation includes `0x00 || len(context) || context` before the message.
HashML-DSA is a different signing mode. It is not a substitute for pure ML-DSA applied to the composite representative.

For pure SSH ML-DSA, revision 08 specifies `string algorithm; string raw_public_key` and `string algorithm; string raw_signature`.
The exact names are `ssh-mldsa-44`, `ssh-mldsa-65`, and `ssh-mldsa-87`. The ML-DSA context is empty.
Section 5 discusses seed retention but leaves the private file format out of scope.
The initial revision 00 contains inconsistent names. It is not the basis for these findings.

For `ssh-mldsa44-ed25519`, composite-00 specifies these concatenations, with no component-length fields inside them:

```text
raw public key  = ML-DSA-44 public key[1312] || Ed25519 public key[32]    (1344)
raw private key = ML-DSA seed[32] || Ed25519 seed[32]                  (64)
raw signature   = ML-DSA-44 signature[2420] || Ed25519 signature[64]    (2484)
SSH public key  = string algorithm || string raw_public_key
SSH agent key   = string algorithm || string raw_public_key || string raw_private_key
SSH signature   = string algorithm || string raw_signature
```

The private-key layout in section 4.1.4 is explicitly for SSH agents. The draft excludes on-disk formats from its scope.
Using the same seed-only basis in OpenSSH files is the maintainer's requirement, not a complete file specification from this draft.
The normal OpenSSH file envelope and interoperability evidence remain separate concerns.

The composite signature representative and component operations are:

```text
Prefix = ASCII("CompositeAlgorithmSignatures2025")
Label  = ASCII("COMPSIG-MLDSA44-Ed25519-SHA512")
ctx    = empty byte string
M'     = Prefix || Label || 0x00 || SHA512(M)
mldsa  = ML-DSA-44.Sign(ml_private_key, M', context=Label)
ed     = Ed25519.Sign(ed_private_key, M')
```

The empty composite `ctx` and the nonempty ML-DSA component context `Label` are different inputs.
Both component signatures must pass. Simply signing `M` with both keys, or using an empty ML-DSA component context, is incompatible.
Section 5 also prohibits reusing component key material between composite and non-composite keys or between composite keys.
Composite-00 lists 4896 bytes for the ML-DSA-87 signature in its P384 variant. FIPS 204 gives 4627 bytes.
4896 is the expanded private-key length. This draft discrepancy must not become a shared ML-DSA signature size.

RFC 9881 uses algorithm identifiers `2.16.840.1.101.3.4.3.17`, `.18`, and `.19` for ML-DSA-44/65/87.
Their AlgorithmIdentifier parameters are absent, not ASN.1 NULL.
The X.509 SubjectPublicKeyInfo BIT STRING contains the raw public key.
PKCS#8 `privateKey` is an OCTET STRING containing one of these DER-encoded choices:

```text
seed        [0] IMPLICIT OCTET STRING (SIZE(32))    inner bytes: 80 20 <32-byte seed>
expandedKey OCTET STRING                           inner tag: 04
both        SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }   inner tag: 30
```

DER is the canonical binary encoding for ASN.1 values.
The `80 20` value is nested inside the PKCS#8 OCTET STRING. A raw seed or an OCTET STRING with a different tag is not equivalent.
A minimal version-0 seed-only PKCS#8 value is 54 bytes for every parameter set.
The final OID byte selects the parameter set.
RFC 9881 recommends seed retention and seed consistency testing when the encoding contains both forms.
The maintainer's possible tolerance for SSH seed-plus-expanded input is not a blanket PKCS#8 consistency policy.

### 9.5 JCA/JCE availability and measured provider differences

[JEP 497](https://openjdk.org/jeps/497) delivered ML-DSA in JDK 24.
Standard `KeyPairGenerator`, `KeyFactory`, and `Signature` accept `ML-DSA`, `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`.
The generic generator defaults to ML-DSA-65 in OpenJDK. Explicit parameter-set names avoid depending on that default.
`NamedParameterSpec.ML_DSA_44/65/87` are newer API constants. The parameter-specific factory names need only Java 8 APIs.
`PKCS8EncodedKeySpec` and `X509EncodedKeySpec` also exist on Java 8. No reflective JCA invocation is needed for those operations.
Newer key interfaces and constants belong in version-specific code when used.

The ordinary `BC` provider supplies the same pure JCE names in `bcprov-jdk18on`.
The [1.79 provider mapping](https://github.com/bcgit/bc-java/blob/r1rv79/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/MLDSA.java) already registers them.
The [1.86 mapping](https://github.com/bcgit/bc-java/blob/r1rv86/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/MLDSA.java) was read and its jar tested.
BC 1.79 was source-inspected for names only. Its seed behavior was not tested.
Ordinary BC needs no separate `BCPQC` provider for these algorithms.
BC's `HASH-ML-DSA` and `ML-DSA-44/65/87-WITH-SHA512` names are not the SSH pure algorithms.

The following results apply to all three parameter sets:

| Runtime/provider | KPG, KF, pure Signature | Seed-only PKCS#8 import/export | Generated private encoding | Nonempty ML-DSA context |
|---|---|---|---|---|
| JDK 21.0.10, built-in SUN | Not available | Not available | Not available | Not available |
| OpenJDK 24.0.2, SUN | Available | Rejected on import | Expanded only | Rejected |
| OpenJDK 25.0.2, SUN | Available | Rejected on import | Expanded only | Rejected |
| OpenJDK 27, SUN | Available | Accepted and preserved | Seed only | Rejected |
| BC 1.86 on JDK 21/24/25/27 | Available | Accepted and preserved | Seed plus expanded | Accepted through BC `ContextParameterSpec` |

KPG means `KeyPairGenerator`. KF means `KeyFactory`.
These are tested releases, not a guarantee about vendor backports or future JDKs.
OpenJDK 26 GA source still discards the generated seed, like 24/25. No JDK 26 runtime probe ran.
The [24 GA source](https://github.com/openjdk/jdk/blob/jdk-24-ga/src/java.base/share/classes/sun/security/provider/ML_DSA_Impls.java) generates an expanded key and clears its seed.
The [27 GA source](https://github.com/openjdk/jdk/blob/jdk-27-ga/src/java.base/share/classes/sun/security/provider/ML_DSA_Impls.java) retains the seed and adds RFC 9881 expansion handling.

Generated SUN expanded PKCS#8 lengths on 24/25 were 2588, 4060, and 4924 bytes.
Generated BC seed-plus-expanded lengths were 2626, 4098, and 4962 bytes.
Seed-only imports exported 54 bytes on BC 1.86 and SUN 27, with inner bytes `80 20 <seed>`.
`KeyFactory.getKeySpec(key, PKCS8EncodedKeySpec.class)` gave the same encoding lengths as `PrivateKey.getEncoded()`.
SUN 24/25 accepted expanded-only PKCS#8, but rejected both seed-only and seed-plus-expanded input with `InvalidKeySpecException`.
SUN 27 and BC 1.86 accepted and preserved all three RFC 9881 forms.
Expanded-only input cannot later yield a seed merely by changing its output encoding.

X.509 public-key encoding lengths were 1334, 1974, and 2614 bytes.
Signatures were 2420, 3309, and 4627 bytes, and generated pairs passed sign/verify.
Converting public keys through X.509 and private keys through expanded-only PKCS#8 allowed cross-provider pure sign/verify in both directions.
These passed on SUN 24/25/27 and BC 1.86 for all parameter sets.
This demonstrates empty-context primitive compatibility, not SSH interoperability or a known-answer test.

BC exposes `MLDSAPrivateKey.getSeed()`, `getPublicKey()`, and `getPrivateKey(true)` for seed-preferred export.
Those are provider-specific conveniences, not common JCE interfaces for the SSH API.
A standard encoded-key path can import a seed-only PKCS#8 value and decode an exported seed or both value without exposing BC types.
Generated-key seed export still requires an encoding that retains the seed.
Generic `PublicKey` and `PrivateKey` also do not define a universal public-key recovery operation.

The context limitation is a separate blocker from seed encoding.
BC 1.86 accepts `Signature.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(label))` before initialization and message input.
The BC probe signed with a nonempty context, passed verification with that context, and failed with an empty context.
SUN 24/25/27 reject that parameter with `InvalidAlgorithmParameterException: The ML-DSA algorithm does not take any parameters`.
Their implementation fixes the ML-DSA context to empty. There is no common standard `java.security.spec.ContextParameterSpec` on these tested runtimes.
Prepending the label to the message cannot replace the context because FIPS 204 encodes the context length separately.
Therefore, SUN's pure `Signature` service cannot directly implement the pinned composite draft, even on JDK 27.

### 9.6 Reproducing the seed and context checks

The probes used `bcprov-jdk18on-1.86.jar` from Maven Central, not a project dependency change.
Its SHA-256 was `2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f`.
Providers were passed explicitly as `Provider` instances. BC was not added to the global provider list.
The following reduced probe reproduces the key availability, seed round trip, and context capability checks.
Its all-zero seed is test data only. It must never be used for real keys.

Save the snippet as `Phase0Probe.java` outside the repository. Place the downloaded BC jar in the same directory.
Compile with `javac Phase0Probe.java`, then run each selected JDK with `java -cp .:bcprov-jdk18on-1.86.jar Phase0Probe`.
The source compiles without a BC dependency because reflection is used only to load the optional probe provider and context class.

```java
import java.security.*;
import java.security.spec.*;

public class Phase0Probe {
    public static void main(String[] args) throws Exception {
        System.out.println(System.getProperty("java.version"));
        Provider bc = (Provider) Class.forName(
                "org.bouncycastle.jce.provider.BouncyCastleProvider")
                .getConstructor().newInstance();
        for (Provider p : new Provider[] { Security.getProvider("SUN"), bc }) {
            for (int i = 0; i < 3; i++) {
                String name = "ML-DSA-" + new int[] { 44, 65, 87 }[i];
                System.out.println(p.getName() + " " + name);
                try {
                    KeyPair kp = KeyPairGenerator.getInstance(name, p).generateKeyPair();
                    Signature sig = Signature.getInstance(name, p);
                    sig.initSign(kp.getPrivate());
                    sig.update(new byte[] { 1, 2, 3 });
                    byte[] signed = sig.sign();
                    sig.initVerify(kp.getPublic());
                    sig.update(new byte[] { 1, 2, 3 });
                    System.out.println("generated PKCS8=" + kp.getPrivate().getEncoded().length
                            + " signature=" + signed.length + " valid=" + sig.verify(signed));
                    // Version 0 PKCS#8 with absent parameters and [0] IMPLICIT seed.
                    byte[] seedPkcs8 = new byte[54];
                    byte[] prefix = { 0x30, 0x34, 2, 1, 0, 0x30, 0x0b, 6, 9,
                            0x60, (byte) 0x86, 0x48, 1, 0x65, 3, 4, 3, (byte) (17 + i),
                            4, 0x22, (byte) 0x80, 0x20 };
                    System.arraycopy(prefix, 0, seedPkcs8, 0, prefix.length);
                    try {
                        KeyFactory kf = KeyFactory.getInstance(name, p);
                        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(seedPkcs8));
                        System.out.println("seed exported=" + kf.getKeySpec(
                                key, PKCS8EncodedKeySpec.class).getEncoded().length);
                    } catch (GeneralSecurityException e) {
                        System.out.println("seed rejected: " + e);
                    }
                    try {
                        AlgorithmParameterSpec ctx = (AlgorithmParameterSpec) Class.forName(
                                "org.bouncycastle.jcajce.spec.ContextParameterSpec")
                                .getConstructor(byte[].class).newInstance((Object) new byte[] { 1 });
                        Signature.getInstance(name, p).setParameter(ctx);
                        System.out.println("nonempty context accepted");
                    } catch (GeneralSecurityException e) {
                        System.out.println("context rejected: " + e);
                    }
                } catch (GeneralSecurityException e) {
                    System.out.println("algorithm unavailable: " + e);
                }
            }
        }
    }
}
```

Additional standalone probes inspected RFC 9881 inner tags with BC ASN.1 utilities and exercised all three private encodings.
They also performed the cross-provider and context-sensitive sign/verify checks described above.
The source review and provider probes are not repository regression tests, SSH interoperability tests, or cryptographic validation.

### 9.7 Corrected assumptions and remaining alignment limits

The JCE method surface is usable on both provider families for pure, empty-context signatures and encoded keys.
It is not a complete common surface for seed-only keys on JDK 24/25, or for the pinned composite scheme on any tested SUN provider.
An algorithm-name lookup alone cannot establish support for the requested feature.

The existing MR-JAR layout enables newer APIs but does not itself provide ML-DSA support or fix provider capabilities.
BC remains optional. Requiring BC silently, discarding the seed, or substituting an empty component context violates the stated constraints.
These are unresolved capability and maintainer-alignment questions, not implemented workarounds.

The historical ML-KEM-first work order, low-level ML-DSA suggestion, and blanket JDK-24+ seed-import assumption are superseded.
The composite draft is WG-adopted. The pure draft remains an individual draft, despite registered algorithm names.
RFC 9881 is a published RFC, not a draft. Private SSH storage remains seed-only under the maintainer's rule.
No later phase was implemented, and no new implementation plan was written.
