# ML-DSA-87 Transparency Cosignatures

An experimental ML-DSA-87 extension to the C2SP subtree cosignature construction, with an explicit experimental key identifier and reproducible signature vectors.

**Draft 02. No stable release or upstream adoption is claimed.**

[Draft](draft.md) defines the technical scope and limits. [Sources](sources.json) pins the upstream documents. [Cases](cases.json) identifies the positive and negative evaluation cases.

This repository can be reviewed and used independently of the CertConcord framework. It does not require the framework's authority hierarchy, operation objects or deployment. The framework selects this work through a pinned dependency and adds its own integration policy.

Run with Node.js 24.15 or later:

    npm run check
    npm test
    python3 tools/verify-key-candidate-accessor-vectors.py
    python3 tools/verify-candidate-array-vectors.py
    python3 tools/verify-candidate-record-vectors.py
    python3 tools/verify-keyobject-boundary-vectors.py
    python3 tools/verify-proof-array-vectors.py
    python3 tools/verify-proof-buffer-vectors.py
    python3 tools/verify-root-buffer-vectors.py
    python3 tools/verify-response-buffer-vectors.py
    python3 tools/verify-context-root-vectors.py
    python3 tools/verify-key-hint-buffer-vectors.py
    python3 tools/verify-signature-verify-buffer-vectors.py
    python3 tools/verify-log-key-id-buffer-vectors.py
    python3 tools/verify-checkpoint-accessor-vectors.py
    python3 tools/verify-revoked-keyobject-vectors.py
    python3 tools/verify-subtree-consistency-vectors.py
    python3 tools/verify-subtree-response-auth-vectors.py
    python3 tools/verify-subtree-http-vectors.py
    python3 tools/verify-subtree-http-client-vectors.py
    python3 tools/verify-subtree-http-interop-vectors.py
    python3 tools/verify-subtree-live-sign-vectors.py
    python3 tools/verify-subtree-cross-runtime-vectors.py
    python3 tools/verify-subtree-cross-runtime-checkpoint-vectors.py
    python3 tools/verify-subtree-python-http-vectors.py
    python3 tools/verify-subtree-boundary-matrix-vectors.py
    python3 tools/verify-subtree-large-u64-vectors.py
    python3 tools/verify-subtree-large-u64-http-vectors.py
    python3 tools/verify-subtree-proof-limit-vectors.py
    python3 tools/verify-subtree-max-carriage-vectors.py

The last eight verifiers use the test-only `pqcrypto` 1.0.0 package. Install it in a virtual environment with the wheel hashes in `tools/requirements-cross-runtime.txt` before running them. The Python HTTP verifier starts a loopback witness peer and invokes the Node HTTP client for 25 cases. Seven cases compose admitted-key discovery with a fixed Python-signed checkpoint request: two send the exact request and five reject before any POST, including an ML-DSA-44-only registry. CI uses a separate virtual environment for these checks.

The boundary-matrix verifier also uses that test-only package. It checks a frozen 257-leaf ML-DSA-87 checkpoint and six complete positive and six negative request wires. The Node suite checks every aligned interval in 24 synthetic tree sizes on both sides of power-of-two boundaries, with one changed-byte rejection per interval. These are verification fixtures, not a deployed witness or a new C2SP type assignment.

The large-u64 verifier checks three original repeated-leaf trees at selected MTC large-consistency range sizes, with nine complete positive and six changed-byte negative request wires. The largest ordered proof has 48 hashes, within the fixed 63-line C2SP carriage. Python independently reconstructs the virtual tree, signed checkpoints and request bytes. These synthetic fixtures do not copy upstream proof hashes or assign an upstream ML-DSA-87 type.

The separate large-u64 HTTP verifier uses the 8,563-byte final-leaf request and freezes a 6,173-byte valid Python response and an equally long signature for a one-byte-different input. A real Node client sends the request to a Python peer; that peer independently authenticates the checkpoint and proof before returning frozen or fresh response bytes. The test also confirms local rejection sends no POST and a raw bad proof receives HTTP 422. This loopback peer is a test fixture with no deployed witness state or production origin admission policy.

The proof-limit vectors freeze original signed first-leaf requests at tree sizes `2^63`, `2^63+1` and `2^64−1`. Independent Python verification accepts all three mathematical consistency proofs: they contain 63, 64 and 64 hashes. The fixed C2SP transport accepts the 63-line request and rejects both valid 64-line proofs before Merkle verification. A one-byte change to the 63-line proof remains within carriage but fails consistency. This test does not relax the 63-line contract or assign an upstream ML-DSA-87 type.

The maximum-carriage vector combines a 49-character range line, 63 valid proof hashes, 255-byte origin and witness names, and one authenticated ML-DSA-87 checkpoint. Its 9,703-byte request reaches the exact 2,929-character pre-checkpoint parser bound and yields a 6,173-byte signature line. A Node loopback client and witness preserve the request bytes, reject a changed proof before sending, and return 400 or 422 for corresponding raw invalid POSTs. Node generates the frozen signatures; Python independently reconstructs the tree, proof, signed inputs and full positive and negative wires, then verifies the stored signatures under the public key. The bound applies to this selected one-signature profile, not to deployment memory or network limits.

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).

