---
name: mina-sshd-house-style
description: "Use when writing, editing, or reviewing Java code in Apache MINA SSHD (sshd-common, sshd-core, etc.) so it matches the project's house style: Javadoc and @author conventions, private-constructor idiom, argument validation helpers, existing DER/key utilities, formatter and checkstyle rules, comment policy. Also use before submitting a PR or when asked whether code looks hand-written."
---

# MINA SSHD house style

Match the sibling code, not generic Java habits. Before writing a new class, open the closest existing sibling and mirror it
(e.g. a new key decoder mirrors `Ed25519PublicKeyDecoder`; a new utility class mirrors `EdDSAUtils`).

## Formatting and tooling (enforced by the build)

- Format with the project formatter: `./mvnw formatter:format impsort:sort` (config: `sshd-eclipse-formatter-config.xml`).
  Code line limit 128, comment/Javadoc limit 120, 4 spaces, no tabs. Checkstyle hard limit is 180.
- Import groups in order, blank line between groups: `java`, `javax`, `org`, `net`, `io`, `com`, then the rest. No star imports, no static imports, no unused imports.
- Every file starts with the ASF license header (`java-checkstyle-license-header.txt`); Apache RAT checks it.
- Newline at end of file; no multiple blank lines inside a class; `@Override` is mandatory.
- Checkstyle limits: methods <= 150 lines, <= 8 parameters, <= 2 outer types per file.
- Run `./mvnw -pl <module> -am verify` (or at least `checkstyle:check`) before finishing.

## Javadoc

- Every public class gets a Javadoc ending with the project author tag:

  ```java
  /**
   * What it is, in a sentence or two.
   *
   * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
   */
  ```

- Public methods and constants: Javadoc with aligned tags (the formatter aligns them):

  ```java
  /**
   * Retrieves the raw key bytes from a {@link PublicKey}.
   *
   * @param  key                      {@link PublicKey} to get the bytes of
   * @return                          the raw key bytes
   * @throws IllegalArgumentException if the key is not supported
   */
  ```

- Link specs with `@see <a href="https://tools.ietf.org/html/rfcNNNN#section-N">RFCNNNN section N</a>`.

## Idioms

- Utility classes: `final`, private constructor that throws, never an empty body or "// No instance" comment:

  ```java
  private FooUtils() {
      throw new UnsupportedOperationException("No instance allowed");
  }
  ```

- Validate arguments with `Objects.requireNonNull(x, "message")` or `ValidateUtils.checkNotNull / checkTrue / hasContent / checkNotNullAndNotEmpty`
  (`org.apache.sshd.common.util.ValidateUtils`) instead of hand-written `if (...) throw`.
- Use `GenericUtils` for null-safe string/collection checks (`GenericUtils.isEmpty`, `GenericUtils.length`, ...).
- Reuse existing infrastructure before writing new code:
  - DER/ASN.1: `org.apache.sshd.common.util.io.der.DERParser` / `ASN1Object` (see `EdDSAUtils`).
  - Key wire/text encoding: `KeyEntryResolver.encodeString / writeRLEBytes / readRLEBytes`.
  - Provider access: `SecurityUtils.getKeyFactory / getKeyPairGenerator`, registrars via `AbstractSecurityProviderRegistrar`.
  - Constants for SSH key type names live in `KeyPairProvider`; algorithm names in `SecurityUtils`.
- Enums for algorithm tables follow the `Builtin*` naming (`BuiltinCiphers`, `BuiltinSignatures`) or a descriptive CamelCase name (`ECCurves`); avoid all-caps type names.
- Singletons: `public static final X INSTANCE = new X();` with a private constructor, and register through the existing registries.
- Do not use reflection to reach provider-specific APIs unless there is no alternative; if unavoidable, justify it in a one-line comment.
- Keep Java baseline compatibility of the module (see `sshd-common/pom.xml` multi-release setup): no newer-language features in the baseline source set.

## Comments

- Write a comment only for what the code cannot show (a spec reference, a non-obvious constraint). One short line.
- Do not narrate the change ("Phase 2 ...", "deliberately no ..."), the review context, or what the next line does.
- No ticket/phase/plan references in source comments; those belong in the commit message and `docs/changes/`.

## Tests

- JUnit 5, class name `*Test`, in the same package as the code under test, under `src/test/java`.
- Mirror existing test base classes and utilities in `sshd-common/src/test` and `sshd-test` before adding new helpers.
- Interop/container tests go in `sshd-test`, not in `sshd-common`.

## Commits and docs

- Commit subject: `GH-<issue>: short summary` (see `git log`).
- User-visible changes get a line in the matching `docs/changes/<version>.md` and, if relevant, the docs page under `docs/`.
- Do not add new markdown design docs to the source tree for a feature unless asked.

## Review checklist

1. Closest sibling opened and mirrored?
2. License header, `@author`, Javadoc on every public type/member?
3. Private-constructor idiom and validation helpers used?
4. No re-implementation of something in `util.io.der`, `KeyEntryResolver`, `GenericUtils`, `ValidateUtils`?
5. Formatter + impsort run; checkstyle and RAT pass?
6. Comments trimmed to what the code cannot say?
