use crate::crypto::cryptor::{Cryptor, CryptorAsyncReader, CryptorAsyncWriter, CryptorForReading, CryptorForWriting};
use std::borrow::Cow;

/// Adds a layer -- to be applied to IO data,
/// able to encrypt/decrypt (or not) both in and out contents.
///
/// If enabled, a naive encryption is done with the `XChaCha20` algorithm,
/// which is a stream cipher. This implementation is designed to work with
/// data chunks and does not require the entire payload to be in memory.
///
/// Security notes:
///
/// Although the code here is not optimal, regarding information security,
/// it does not introduce waker vulnerabilities than having the `key` as
/// plain text in the config file, as we do have today.
///
/// That being put, we have:
///
///  1) No MAC (Message Authentication Code). If the attacker changes the encrypted file contents,
///     the decrypted file will be different from the original. We have no means to detect that.
///     But, to cause meaningful harm, the attacker would have to execute several iterations of
///     "change a byte on the encrypted file, perform a scan, see if there was a parsing error or if
///     the property he wants to tweak have changed". It would be easier to execute the application in
///     debug mode and changed the values in the decrypted buffers.
///
/// Conclusions:
///  a) We are not adding a weaker link to the security chain than having the key exposed in the plaintext config file
///  b) The effort to exploit the vulnerabilities contained here are more expensive than simply debugging
///     the application's execution in, e.g., `gdb`.
pub struct Encryptable;

impl Encryptable {
    pub fn for_reading(key: Option<&[u8; 32]>) -> EncryptableForReading {
        EncryptableForReading::new(key.map(Cryptor::for_reading))
    }

    pub fn for_writing(key: Option<&[u8; 32]>) -> EncryptableForWriting {
        EncryptableForWriting::new(key.map(Cryptor::for_writing))
    }
}

pub struct EncryptableForReading<'a> {
    cryptor: Option<CryptorForReading<'a>>,
}

impl<'a> EncryptableForReading<'a> {
    fn new(cryptor: Option<CryptorForReading<'a>>) -> Self {
        Self {
            cryptor,
        }
    }
    pub fn input<'b>(&mut self, chunk: &'b mut [u8]) -> &'b [u8] {
        if let Some(cryptor) = self.cryptor.as_mut() {
            cryptor.input(chunk)
        } else {
            chunk
        }
    }
}

pub struct EncryptableForWriting {
    cryptor: Option<CryptorForWriting>,
}

impl EncryptableForWriting {
    fn new(cryptor: Option<CryptorForWriting>) -> Self {
        Self {
            cryptor,
        }
    }

    pub fn output_in_place<'a>(&mut self, chunk: &'a mut [u8]) -> Cow<'a, [u8]> {
        if let Some(cryptor) = self.cryptor.as_mut() {
            cryptor.output_composed_in_place(chunk)
        } else {
            Cow::Borrowed(chunk)
        }
    }

    pub fn output_ro<'a>(&mut self, chunk: &'a [u8]) -> Cow<'a, [u8]> {
        if let Some(cryptor) = self.cryptor.as_mut() {
            Cow::Owned(cryptor.output_ro(chunk))
        } else {
            Cow::Borrowed(chunk)
        }
    }
}

// Tokio's Async Read & Write integration
/////////////////////////////////////////
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::Result;

pub enum EncryptableAsyncReader<'a, InnerAsyncReaderType> {
    Plain(InnerAsyncReaderType),
    Encrypted(CryptorAsyncReader<'a, InnerAsyncReaderType>),
}

impl<'a, InnerAsyncReaderType: tokio::io::AsyncRead + Unpin> EncryptableAsyncReader<'a, InnerAsyncReaderType> {
    pub fn new(inner: InnerAsyncReaderType, key: Option<&'a [u8; 32]>) -> Self {
        match key {
            Some(key) => Self::Encrypted(CryptorAsyncReader::new(inner, key)),
            None => Self::Plain(inner),
        }
    }
}

impl<'a, InnerAsyncReaderType: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for EncryptableAsyncReader<'a, InnerAsyncReaderType> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        match self.get_mut() {
            Self::Plain(plain_async_reader) => std::pin::pin!(plain_async_reader).poll_read(cx, buf),
            Self::Encrypted(cryptor_async_reader) => std::pin::pin!(cryptor_async_reader).poll_read(cx, buf),
        }
    }
}

pub enum CryptableAsyncWriter<InnerAsyncWriterType> {
    Plain(InnerAsyncWriterType),
    Encrypted(CryptorAsyncWriter<InnerAsyncWriterType>),
}

impl<InnerAsyncWriterType: tokio::io::AsyncWrite + Unpin> CryptableAsyncWriter<InnerAsyncWriterType> {
    pub fn new(inner: InnerAsyncWriterType, key: Option<&[u8; 32]>) -> Self {
        match key {
            Some(key) => Self::Encrypted(CryptorAsyncWriter::new(inner, key)),
            None => Self::Plain(inner),
        }
    }
}


impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CryptableAsyncWriter<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        match self.get_mut() {
            Self::Plain(plain_async_reader) => std::pin::pin!(plain_async_reader).poll_write(cx, buf),
            Self::Encrypted(cryptor_async_reader) => std::pin::pin!(cryptor_async_reader).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.get_mut() {
            Self::Plain(plain_async_reader) => std::pin::pin!(plain_async_reader).poll_flush(cx),
            Self::Encrypted(cryptor_async_reader) => std::pin::pin!(cryptor_async_reader).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.get_mut() {
            Self::Plain(plain_async_reader) => std::pin::pin!(plain_async_reader).poll_shutdown(cx),
            Self::Encrypted(cryptor_async_reader) => std::pin::pin!(cryptor_async_reader).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
    use super::*;

    #[test]
    fn plain_text() {
        let expected = b"To this payload, no encryption is applied because we do not provide a key to `Cryptable::new()`";

        // assert no encryption
        let mut cryptable = Encryptable::for_writing(None);
        let outgoing = cryptable.output_ro(expected);
        assert_eq!(
            outgoing.as_ref(),
            expected,
            "`output()` did not return the same plain chunk"
        );

        // assert no decryption
        let mut cryptable = Encryptable::for_reading(None);
        let mut outgoing = outgoing.into_owned();
        let incoming = cryptable.input(&mut outgoing);
        assert_eq!(
            incoming,
            expected,
            "`input()` did not return the same plain chunk"
        );
    }
    #[test]
    fn happy_enc_dec() {
        let expected = b"Now this payload must be encrypted/decrypted, as we do provide a key to `Cryptable::new()`. Additional tests are in the `Cryptor` module";
        let key = b"123456789 123456789 123456789 12";

        let mut cryptable = Encryptable::for_writing(Some(key));
        let outgoing = cryptable.output_ro(expected);
        assert_ne!(
            outgoing.as_ref(),
            expected,
            "`output()` shouldn't return the same plain chunk"
        );

        let mut cryptable = Encryptable::for_reading(Some(key));
        let mut outgoing = outgoing.into_owned();
        let incoming = cryptable.input(&mut outgoing);
        assert_eq!(
            incoming,
            expected,
            "`output()` => `input()` encryption/decryption round-trip didn't work"
        );
    }

    #[tokio::test]
    async fn async_read_write_plain_text() {
        let payload = b"Hello, plain-text world!";

        // Create a mock in-memory buffer to act as our "stream"
        let mut output_buffer: Vec<u8> = Vec::new();

        // Use a cursor to simulate a writeable stream
        let mut writer = CryptableAsyncWriter::new(&mut output_buffer, None);
        writer.write_all(payload).await
            .expect("Couldn't write");
        writer.flush().await
            .expect("Couldn't flush");

        println!("Original:          #{}", payload.len());
        println!("Plain-text output: #{}", output_buffer.len());

        // Now, create a reader to read from the buffer
        let mut reader = EncryptableAsyncReader::new(output_buffer.as_slice(), None);
        let mut input_data = Vec::new();
        reader.read_to_end(&mut input_data).await
            .expect("Couldn't read");

        println!("Plain-text input: #{}", input_data.len());
        println!("Plain-text input: {}", String::from_utf8_lossy(&input_data));
        assert_eq!(&input_data, payload);
    }

    #[tokio::test]
    async fn async_read_write_encrypted() {
        let key = b"123456789 123456789 123456789 12";
        let payload = b"Hello, encrypted world!";

        // Create a mock in-memory buffer to act as our "stream"
        let mut encrypted_buffer: Vec<u8> = Vec::new();

        // Use a cursor to simulate a writeable stream
        let mut writer = CryptableAsyncWriter::new(&mut encrypted_buffer, Some(key));
        writer.write_all(payload).await
            .expect("Couldn't write");
        writer.flush().await
            .expect("Couldn't flush");

        println!("Original:  #{}", payload.len());
        println!("Encrypted: #{}", encrypted_buffer.len());

        // Now, create a reader to read from the buffer
        let mut reader = EncryptableAsyncReader::new(encrypted_buffer.as_slice(), Some(key));
        let mut decrypted_data = Vec::new();
        reader.read_to_end(&mut decrypted_data).await
            .expect("Couldn't read");

        println!("Decrypted: #{}", decrypted_data.len());
        println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_data));
        assert_eq!(&decrypted_data, payload);
    }

    #[tokio::test]
    async fn async_read_write_encrypted_big_sheets() -> tokio::io::Result<()> {
        let file_path = "/tmp/big.encrypted";
        let key = b"123456789 123456789 123456789 12";
        let payload = || (0..(1<<22)).map(|i| i.to_string());
        let buffer_size = 1<<13;

        // Create the encryptable file for writing with a buffer
        let encrypted_file = tokio::fs::File::create(file_path).await?;
        let encrypted_writer = CryptableAsyncWriter::new(encrypted_file, Some(key));
        let mut writer = BufWriter::with_capacity(buffer_size, encrypted_writer);

        // write all the stuff
        for i in payload() {
            writer.write_all(i.as_bytes()).await?;
        }
        writer.shutdown().await?;
        drop(writer);

        println!("Wrote.");

        // Create the decryptable reader with a buffer
        let encrypted_file = tokio::fs::File::open(file_path).await?;
        let encrypted_reader = EncryptableAsyncReader::new(encrypted_file, Some(key));
        let mut reader = BufReader::with_capacity(buffer_size, encrypted_reader);

        // read all the stuff and compare
        let mut file_offset = 0;
        let mut observed = Vec::with_capacity(1 + payload().len() / 10);
        for expected in payload() {
            #[allow(clippy::uninit_vec)]
            unsafe { observed.set_len(expected.len()) };
            reader.read_exact(&mut observed).await
                .unwrap_or_else(|err| panic!("Failed reading past {expected}-1: {err}"));
            assert_eq!(observed, expected.as_bytes(), "Failed at #{expected} @ file offset {file_offset} -- buffer size is {buffer_size}");
            file_offset += expected.len();
        }

        Ok(())
    }

}