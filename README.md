# encryptable-tokio-fs

A drop-in, API-identical replacement for `tokio::fs` with transparent opt-in, non-framing stream cipher encryption.

This crate _is_ *aims to be* a full API mirror of `tokio::fs`. When a cryptographic key is provided, data is automatically encrypted/decrypted using the `XChaCha20` stream cipher during file reads and writes, requiring zero application-side code changes.

To use it:
1) Search and replace all `tokio::fs` for `encryptable-tokio-fs::fs`
2) To enable encryption, call `encryptable-tokio-fs::fs::set_key()`. All file operations, from that point on, will be encrypted.
3) By not setting a key, file operations will be exactly the same as `tokio::fs` -- a.k.a., "plain-text".

## Example
```rust
#[tokio::main]
async fn main() {
    use encryptable_tokio_fs::fs;
    const CONTENTS: &[u8] = b"Congrats! The contents had been successfully written and read back! Now go and inspect the actual file contents!";
    const FILE: &str = "/tmp/wr.file";

    // comment/uncomment to see the file being written in plain/encrypted modes
    fs::set_key(*b"123456789 123456789 123456789 12");
    // the above is really bad: do not place keys inside the binary.
    // If unavoidable -- e.g., to load initial configs where the
    // per-customer key resides -- use `litcrypt`.

    fs::write(FILE, CONTENTS).await
        .expect("Failed to write to file");

    let contents = fs::read(FILE).await
        .expect("Failed to read from file");

    println!("{}", String::from_utf8_lossy(&contents));

}
```

## Use case

This crate was designed to hide data at rest on programs shipped to stakeholders, executing on their premises. If an attacker is able to run the program in a debugging session,
the encryption key might be known and any elaborated security models would become ephemeral. Please see more in `Security model` and a proposed "quick fix" at the end of this document.

## Pre-release API

We are in the pre-release API, where only a small -- but very useful -- portion of the whole API is implemented.

Specifically, the `CryptorAsyncReader` & `CryptorAsyncWriter` are fully implemented, effectively allowing
the replacement `File` object to be encrypted. 

On the other side, we are still lacking:
1) File Name & Path encryption
2) Traversing the filesystem (encrypted portion of it)
3) Seek support
4) Append support (this would require seek, as the cypher needs also to read the headers and seek the cypher to the end position)


## Implementation Status

Although the API is still very simplistic, the implementation is efficient, secure, decoupled, and has been fully tested.

Your inputs are welcome to guide further development. Please create a `Github Issue` with requests or suggestions.

## Global context vs Instantiated

On the above usage example, a single key would be used for all file operations -- since the easiest integration path is
to keep using the global context, exactly as `tokio` does.

Nonetheless, there will be APIs to instantiate the cryptor FS layer -- allowing multiple keys to be used simultaneously.

Using the global context is easier, but has the downside to require the key to be stored in RAM until the process ends, which may be
of concern if you are executing it in adverse environments.

## Security model

This crate provides confidentiality only: it encrypts bytes so they are unreadable without the key.
It does not provide integrity or authenticity.

What you get: secrecy of file contents (assuming key secrecy).

What you do not get: detection of modifications, truncation, re-ordering, or header tampering. Any bit flips or edits to the encrypted file will decrypt to some bytes without error.

Corruption/tampering: disk glitches or malicious edits are not detected. We keep an integrity parity with plaintext: Using this crate for encrypted files provides no more and no less
modification detection than storing plain-text. If your application requires modification detection, we recommend you to add your own checks for it to work for both encrypted or
non-encrypted contents -- If you only care about accidental corruption (not adversaries), add a filesystem-level checksum (e.g., CRC32/64) or hash stored elsewhere and verify before use.

Threat model: equivalent to a plain-text file with OS-level permissions for integrity. If an attacker can modify the file, they can change the decrypted output without this crate noticing.

We do not defend against malicious changes.

However, there is a caveat: if any of the first 192 bits of any encrypted file are changed (the nonce header), the full contents of the file will become garbage.

Why this design: files remain seekable with raw stream encryption; adding per-frame authentication would change that trade-off. This crate intentionally keeps the plain-text-like
ergonomics for reading/seek.

## No seek, possibly support append, but solving the integrity & authentication issues Trade-off

By incorporating compression, we may solve all the issues raised in the security model above -- at the expense of losing seek support.
Maybe we can work with both variants:
1) `encryptable-tokio-fs::fs::set_key()` -- enables encryption (but no integrity nor authentication) and supports the full `tokio::fs` API.
2) `encryptable-tokio-fs::fs::set_compressor()` -- enables compression (possibly on top of encryption): provides integrity & authentication (immune to "casual attacks") but disables `seek` and, possibly, `append`.

To further improve a little bit on the security -- provided an attacker is not able to conduct a debugging session:
* No compressor error message will leak. It will just fail with "tempered data";
* Before shouting "tempered data", a sleep of 1 second will be enforced;
* Users are strongly advised to hide -- as much as possible -- the contents of the encrypted files.
  If unavoidable, the further delaying presenting this information the better. E.g.: if `--verbose` is enabled,
  sleep for 1 second before starting the program.

With these additions, we estimate the cost for a determined attacker to effectively change a "license expiry date" on a yaml file to be at around ~40k.
Please do not use this crate to secure higher valuable assets.

The above cost holds true provided you obfuscate the binary enough to make debugging sessions fruitless:
* Binary building options: strip debug info, use aggressive linking optimizations (fat), use codegen-units = 1, panic = abort, statically link as most as possible.

and bail out if a debugger has been detected:
* Linux: Check the `P_TRACED` flag in the `/proc/self/status` file or use the `ptrace` system call (the well-known "ptrace trick")
* Windows: Call the `IsDebuggerPresent()` function from the WinAPI, or check the `BeingDebugged` flag in the Process Environment Block (PEB)
* You can also search among process names for known debuggers: gdb, lldb, x64dbg, ollydbg, ...