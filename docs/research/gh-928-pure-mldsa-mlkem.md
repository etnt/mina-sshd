# Research: GH-928 – pure ML-DSA signatures and pure ML-KEM key exchanges

Issue: https://github.com/apache/mina-sshd/issues/928 (open, no assignee)

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

> Caveat: the wire names, sizes and encodings above come from memory of the drafts. Verify them against the current draft text before coding. The Bouncy Castle class names were not checked against the jar (it was not in the local Maven repository).
