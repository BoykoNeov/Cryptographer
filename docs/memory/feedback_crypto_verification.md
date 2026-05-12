---
name: feedback-crypto-verification
description: "For new cipher implementations, get an external oracle (reference library) BEFORE writing tests against assumed published values."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: ce93695d-d322-4faa-a8fa-e84a14fc9768
---

For any new cipher (ChaCha20, RSA, future Serpent modes, etc.), the FIRST test should be a single KAT against an external reference implementation — not against published test vectors quoted from web search or memory.

**Why:** Test vectors in circulation use inconsistent conventions. "Serpent key = 80…0" appears in multiple references with DIFFERENT expected ciphertexts depending on bit-numbering (MSB-first vs LSB-first) and byte-order conventions. Pinning a wrong expected value sends you debugging a correct implementation against a wrong target.

**How to apply:**

1. Install a reference: Python (`CryptoPlus`, `pycryptodome`, `cryptography`), an npm package, or use `node:crypto`/OpenSSL CLI if the cipher is there.
2. Run one encryption with a chosen `(key, plaintext)`. Capture the output as the FIRST KAT.
3. Implement the cipher iteratively against that KAT — get round-key 0 matching first, then round 0 state, etc.
4. Only AFTER the KAT matches, add roundtrip and structural tests as a regression net.

**Anti-pattern to avoid:** Writing 18 files and 90+ structural/roundtrip tests, then trying to verify with cited published KATs at the end. Roundtrip tests pass for any self-consistent convention — they're necessary but not sufficient for cryptographic correctness. This happened during the Serpent landing (May 2026); a Python reference cross-check revealed a hybrid IP-plus-bitslice bug that round-tripped fine but produced wrong absolute ciphertexts.

**Related project pitfalls:** see [[CLAUDE.md "Serpent has two equivalent forms — don't mix them" and "Serpent test vectors must be verified against an oracle, not assumed"]].

**Python setup gotcha encountered:** `CryptoPlus.Cipher.pyserpent` on Python 3.14 + setuptools 82 needs a `pkg_resources` shim: `sys.modules['pkg_resources'] = types.ModuleType('pkg_resources'); sys.modules['pkg_resources'].parse_version = lambda x: tuple(int(p) for p in x.split('.') if p.isdigit())`. Then `from CryptoPlus.Cipher.pyserpent import Serpent` works.
