# encryptable-tokio-fs

A drop-in, API-identical replacement for `tokio::fs` with transparent opt-in, non-framing stream cipher encryption.

This module is a full API mirror of `tokio::fs`. When a cryptographic key is provided, data is automatically encrypted/decrypted using the XChaCha20 stream cipher during file reads, writes, and appends, requiring zero application-side code changes.

To use it:
1) Search and replace all `tokio::fs` for `encryptable-tokio-fs::fs`
2) To enable encryption, call `encryptable-tokio-fs::fs::set_key()`. All file operations, from that point on, will be encrypted.
3) By not setting a key, file operations will be exactly the same as `tokio::fs` -- a.k.a., "plain-text".

# Global context vs Instanciated

On the above usage example, a single key would be used for all file operations -- since the easiest integration path is
to keep using the global context.

Nonetheless, there are APIs to instantiate the encryptable FS layer 

## Pre-release API

We are in the pre-release API, where only the `CryptableAsyncReader` & `CryptableAsyncWriter` are implemented.

This is good for a great deal of file operations, but still lacking:
1) File Name & Path encryption
2) Traversing the filesystem (encrypted portion of it)
3) Seek support
4) Append support (this would require the full file open FS + seek, as the cypher needs also to read the headers and seek to the same position)


## Implementation Status

Although the API is still very simplistic, the implementation is efficient, secure, decoupled, and has been fully tested.

## Security model

This crate provides confidentiality only: it encrypts bytes so they are unreadable without the key.
It does not provide integrity or authenticity.

What you get: secrecy of file contents (assuming key secrecy).

What you do not get: detection of modifications, truncation, re-ordering, or header tampering. Any bit flips or edits to the encrypted file will decrypt to some bytes without error.

Corruption/tampering: disk glitches or malicious edits are not detected. We keep an integrity parity with plaintext: Using this crate for encrypted files provides no more and no less
modification detection than storing plaintext. If your application requires modification detection, add your own checks for it to work for both encrypted or non-encrypted outputs.
-- If you only care about accidental corruption (not adversaries), add a filesystem-level checksum (e.g., CRC32/64) or hash stored elsewhere and verify before use. This does not defend against malicious changes.

Threat model: equivalent to a plaintext file with OS-level permissions for integrity. If an attacker can modify the file, they can change the decrypted output without this crate noticing.

However, there is a caveat: if any of the first 192 bits of each file are changed (the nonce header), the full contents of the file will be lost.

Why this design: files remain seekable with raw stream encryption; adding per-frame authentication would change that trade-off. This crate intentionally keeps the plaintext-like ergonomics for reading/seek.

When not to use this crate: configuration that gates security decisions, self-describing formats that could be abused by bit flips, or any scenario where undetected modification is unacceptable.

Terminology note: “encryption” here means confidentiality. If you need authenticated encryption (confidentiality and integrity), use an AEAD.