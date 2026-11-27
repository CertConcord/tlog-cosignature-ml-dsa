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

The last verifier uses the test-only `pqcrypto` 1.0.0 package. Install it in a virtual environment with the wheel hashes in `tools/requirements-cross-runtime.txt` before running that command. CI uses a separate virtual environment for this check.

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).

