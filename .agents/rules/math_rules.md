# Mathematical & Forensic Invariants (`math_rules.md`)

> **Memory Category:** Declarative Domain Rule
> **Source:** Project domain invariants (`VerificatorCore`)
> **Version / Date:** 1.1.0 (2026-11-10)
> **Last Reviewed:** 2026-11-10
> **Change Summary:** Adapted for `VerificatorCore` 4-layer forensic decision lattice, SHA-256 verification, and version comparison invariants.
> **Scope:** Zero false-positive verdict lattice (`IntegrityVerdict`), cryptographic digest verification (`UpdateChecksums`, `UpdateSignature`), and semantic version ordering (`AppUpdateChecker.isNewer`).

---

## 1. Zero False-Positive Forensic Decision Lattice (`ForensicScanner`)

1. **Verdict Ordering:**
   $$\texttt{clean} < \texttt{warning} < \texttt{tampered}$$
2. **Official Chain Immunity (`hasOfficialAppleChain`):**
   A bundle whose authority chain contains `Apple Root CA`, `Developer ID Application`, `Apple Mac OS Application Signing`, `Apple iPhone OS Application Signing`, or `Software Signing` and passes `codesign --verify --no-strict` without injected mismatched dylibs **MUST** evaluate to `IntegrityVerdict.clean`.
3. **Signature Hijack Predicate (`isSignatureHijacked`):**
   $$\text{Hijacked} \iff \text{hasOfficialVendorFramework} \land (\text{mainSig.isAdhoc} \lor \text{mainSig.isUnsigned} \lor \neg\text{mainSig.hasOfficialAppleChain}) \land (\text{hasAdhocOrUnsignedInMacOS} \lor \text{hasDifferentSignerDylib})$$

---

## 2. Cryptographic & Version Ordering Invariants (`AppUpdate`)

1. **SHA-256 Digest Verification (`UpdateChecksums.sha256`):**
   Streams files in $2^{20}$-byte ($1\text{ MiB}$) chunks and produces a 64-character lowercase hexadecimal digest.
2. **Lexicographical Component Version Comparison (`AppUpdateChecker.isNewer`):**
   Strips leading `v`/`V`, splits on `.`, pads missing trailing components with `0`, and compares integer components left-to-right.
