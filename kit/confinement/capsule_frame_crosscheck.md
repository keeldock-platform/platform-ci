CAPSULE FRAME VECTOR CROSS-CHECK

The manual capsule-vectors workflow runs only from reviewed main. Its first step
refuses every other event or ref. The Windows job fetches the public control
commit, checks its exact SHA and policy, compiles capsule_frame.cs through the
PowerShell driver, and generates deterministic vectors. It uploads the JSON as
one short-retention artifact for review and sends the same data, compressed, to
an Ubuntu comparison job. Both jobs have empty permissions. The only action is
the repository's pinned artifact uploader. No secret or private source enters
either job. A final job emits one capsule-vectors verdict line and fails unless
generation and comparison both succeeded.

The Windows generation step emits only one fixed refusal line on failure.
Its reasons are compiler_missing, compile_failed, vector_generation_failed,
vector_mismatch, and encoding. The generation step does not forward compiler
diagnostics, unexpected child output, or C sharp source text. A failed or
malformed child result always exits nonzero. A bounded vector shape check
precedes artifact and job-output writes. The workflow policy checks the exact
workflow bytes.

kit/confinement/capsule_frame_vector_gate.py is an explicit CI entry point. Its
name deliberately avoids unittest's ordinary test_ discovery pattern. It
requires both a checked-in generated fixture and fresh CI output. A missing or
pending fixture fails the gate, as does any difference between reviewed and
fresh C sharp JSON. The first capsule-vectors run on main, run 40866237493,
refused only because the checked-in fixture was pending; all other comparisons
matched. The reviewed artifact from that run is now checked in. Its SHA-256 is
fb0660998011eec479ee01e919510dcd8f88ae5266114d9f82a899b4fa72fb94. The next
dispatch is the first capsule-vectors run that counts as protocol coverage.

The gate compares the complete key record, header, canonical manifest CBOR,
header digest, HKDF inputs and outputs, nonces, AAD fields, ciphertext manifest
digest, selected ciphertext digests and tags, and whole-capsule digest against
Python's fixed-input outputs. For AES-GCM, Python binds the Ubuntu platform's
OpenSSL EVP through ctypes, recomputes every encrypted chunk, and feeds bundle
AAD through the Python codec's public make_aad function. The C sharp generator
uses the C sharp codec's public MakeAad function for every bundle chunk. Both
sides check the published SEC2 P-256 base point, RFC 5869 HKDF test case 1,
and NIST zero-key, zero-IV AES-256-GCM empty-message tag. Both sides exercise
tag corruption and bundle-index reset; manifest path negatives include a
file/file alias, a file/directory alias, and unsupported Unicode. The C sharp
decryption negatives first decrypt the unmodified bundle chunk and compare its
plaintext, so an unconditional decryption refusal cannot satisfy them.

The path alphabet is provisionally limited to printable ASCII after the
existing path rules. For every accepted path, Python casefold and C sharp
invariant lowercase therefore produce the same alias. This follows the Python
codec's PROVISIONAL_CHOICES and conservatively refuses Unicode until a reviewed
Windows-equivalence rule is available.

Vector provenance record

The generated JSON carries producer=independent-csharp. This identifies the
generator, not independent authorship. The workflow fixes the producing path as
capsule_frame.cs through PowerShell Add-Type on windows-2025. The Ubuntu gate
requires the capsule-vectors workflow on main and records the public run ID,
attempt, control SHA, generated JSON digest, reviewed fixture digest, and
authorship=unreviewed in a provenance log line. It requires the reviewed JSON
bytes to match the generated artifact bytes, allowing only a trailing newline
in the checked-in file. These facts permit the coordinator to associate the
reviewed artifact with its CI run; they do not establish how the C sharp source
was authored.

Correlated-defect mitigation and open evidence

The C sharp author inspected the Python source during implementation, and the
review found matching parser and validation structure. The gate therefore
checks selected key-record and header bytes against offsets written directly
from the design, in addition to the Python codec comparison. Published
primitive fixtures and Ubuntu OpenSSL independently check the cryptographic
outputs. These checks reduce shared layout and crypto mistakes but cannot
exclude a shared framing, CBOR, or refusal defect. Independent authorship of
those paths, or a separately authored framing/parser oracle, still needs
provenance review. The Python codec's independent-protocol-vectors requirement
stays open even after a matching byte cross-check until that review accepts
the provenance evidence and CI vectors. This workflow also does not prove
leading-zero or byte order with an actual persisted CNG receiver key handle.
That proof, parser fuzzing, and hosted interoperability remain separate design
gates.
