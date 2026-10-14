# Implementation Plan: GH-928 – pure ML-KEM, ML-DSA and composite signatures

Based on: `docs/research/gh-928-pure-mldsa-mlkem.md`

## Guiding rules

- All new algorithms are **experimental and opt-in**. None goes into the defaults in `BaseBuilder` or the default signature list.
- BC stays optional. Load BC classes lazily and report `isSupported()` (pattern in `MLKEM.Parameters`).
- Java 8 baseline. No JDK 24+ API at compile time.
- One PR per phase. Each phase must build and pass tests on its own.
- Every phase ends with docs (`docs/standards.md`, `docs/changes/`) and tests.

## Phase 0 – Alignment and spec verification (about 2 days)

Goal: remove the unknowns before writing code.

1. Comment on GH-928: propose the phased, experimental plan. Ask the maintainers to confirm scope and order.
2. Read the current draft texts and record the exact values in a spec note:
   - KEX names, hashes, and how K is encoded (string or mpint);
   - key type names, public key and signature layout, context string;
   - the composite combiner for `ssh-mldsa44-ed25519` (from OpenSSH 10.5 source).
3. Check the BC 1.86 jar for ML-DSA classes and JCA names (`ML-DSA-44/65/87`) and PKCS#8 support.
4. Build an interop test bed: OpenSSH 10.5 and oqs-openssh containers. Check what the repo's existing container tests use.

Exit: spec note committed; maintainer agreement on the issue.

## Phase 1 – Pure ML-KEM key exchange (about 1–2 days)

Goal: `mlkem768-sha256` and `mlkem1024-sha384` (names as verified in Phase 0).

1. Add constants and enum entries to `BuiltinDHFactories`.
2. Add a KEM-only key-exchange class based on `AbstractDH`. Reuse `MLKEM` and `BuiltinKEM` unchanged.
   - Client `e` = KEM public key. Server `f` = ciphertext.
   - Enforce **exact** lengths (`Server.init` today accepts trailing bytes for hybrids).
   - Encode K as the draft says. Check the `raw` handling in `XDH`.
3. `isSupported()` = BC KEM supported and digest supported.
4. Tests (model: `OpenSshMlKemTest`):
   - round trip client/server;
   - wrong-length public key and ciphertext are rejected;
   - key exchange fails cleanly without BC;
   - interop with oqs-openssh.
5. Docs and change note.

Exit: client and server negotiate pure ML-KEM with the existing host key types; interop passes.

## Phase 2 – ML-DSA key and signature infrastructure (about 1 week)

Goal: a generic ML-DSA key type that Phase 3 and Phase 4 reuse. Parameter sets are a table (`44/65/87`), not copied code.

1. Provider layer
   - `SecurityUtils.isMlDsaSupported()`, and a registrar check.
   - Choose BC JCA (`KeyFactory`, `KeyPairGenerator`, `Signature`) over BC lightweight API. It keeps `KeyPair` and `PublicKey` standard.
2. Key types
   - Constants in `KeyPairProvider`; a helper enum with name, sizes and JCA name.
3. Public keys
   - `PublicKeyEntryDecoder` (model: `GenericEd25519PublicKeyDecoder`).
   - `BufferPublicKeyParser` (model: `ED25519BufferPublicKeyParser`).
   - Register in `KeyUtils` and `BuiltinIdentities`.
4. Private keys
   - OpenSSH private key decoder, with the layout aligned to OpenSSH 10.5 / oqs-openssh.
   - Optional PKCS#8 / PEM parser (model: `Ed25519PEMResourceKeyParser`).
5. Signature
   - `SignatureMlDsa` (extends `AbstractSignature`): `string(name) string(sig)`, empty context, uses `extractEncodedSignature`.
6. Key generation and display
   - `AbstractGeneratorHostKeyProvider` / `SimpleGeneratorHostKeyProvider`, fingerprints, `KeyRandomArt`, `ssh-keygen`-like utilities in `sshd-cli` if present.
7. Tests
   - encode/decode round trip, known-answer vectors from NIST ACVP, wrong-size rejection, signature tamper test.

Exit: ML-DSA keys can be generated, saved, loaded and used to sign and verify in unit tests. Nothing is registered in `BuiltinSignatures` yet.

## Phase 3 – Composite `ssh-mldsa44-ed25519` (about 1 week)

Goal: first user-visible signature algorithm, with real interop (the maintainers' stated priority).

1. Composite key type: public key = ML-DSA-44 key + Ed25519 key, in the layout of the OpenSSH 10.5 implementation.
2. `SignatureMlDsa44Ed25519`: build the combined message (domain label, prehash) exactly as in the spec; verify **both** parts; fail if either fails.
3. Private key and public key decoders for the composite type.
4. Register in `BuiltinSignatures` (`isSupported()` = ML-DSA and Ed25519 both supported). Not in defaults.
5. Tests
   - unit: sign/verify, one-part-tampered must fail;
   - session: server host key and client user key;
   - interop: OpenSSH 10.5 both directions (host key and public-key authentication).
6. Docs and change note.

Exit: a MINA client authenticates to OpenSSH 10.5, and OpenSSH 10.5 to a MINA server, with the composite key.

## Phase 4 – Pure ML-DSA `ssh-mldsa-44/65/87` (about 3–5 days)

Goal: the CNSA 2.0 use case from the issue.

1. Register the three names in `BuiltinSignatures` and `BuiltinIdentities`, using the Phase 2 code.
2. Certificate variants only if the draft defines them. Otherwise skip.
3. Tests: session tests for all three sets; interop with wolfSSH and oqs-openssh.
4. Policy test: configure a pure-PQC-only profile (pure ML-KEM plus pure ML-DSA, nothing else) and check that a session works and that fallbacks are refused. Document the configuration example.
5. Docs and change note.

Exit: pure-PQC-only client and server sessions work and interoperate.

## Phase 5 – Hardening and release (about 2–3 days)

1. Check limits with large keys and signatures: packet size, `authorized_keys` parsing, known_hosts, log output.
2. Performance sanity check: handshake time with each algorithm.
3. Run the full build including the no-BC profile (`classpathDependencyExclude` in `sshd-core/pom.xml`) so nothing fails without BC.
4. Review with the maintainers. Mark all features as experimental in docs and Javadoc.
5. Release notes. Record the follow-ups: re-check the names and the encodings when the drafts become RFCs; consider adding to defaults then.

## Dependencies and order

```
Phase 0 ──> Phase 1 (independent, can ship first)
        └─> Phase 2 ──> Phase 3 ──> Phase 4 ──> Phase 5
```

Phase 1 and Phase 2 can run in parallel. Phase 5 covers all phases.

## Estimated total

About 3–4 weeks for one developer, including interop testing.

## Main risks per phase

| Phase | Risk | Mitigation |
|---|---|---|
| 0 | Maintainers decline | Stop early; keep the research notes |
| 1 | K encoding differs from hybrid code | Verify with a reference implementation test vector |
| 2 | No standard private key layout | Follow OpenSSH 10.5; isolate the decoder |
| 3 | Combiner details wrong | Test against OpenSSH 10.5 binaries before anything else |
| 4 | Draft changes names or format | Keep names in one constants class; experimental label |
