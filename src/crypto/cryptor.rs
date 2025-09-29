//! Like [Cryptable], but always encrypts

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{Key, XChaCha20, XNonce};
use std::borrow::Cow;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub struct Cryptor<'a> {
    key: &'a [u8; KEY_LEN],
}

impl<'a> Cryptor<'a> {
    pub fn for_reading(key: &'a [u8; KEY_LEN]) -> CryptorForReading<'a> {
        CryptorForReading::new(Self {
            key,
        })
    }

    pub fn for_writing(key: &'a [u8; KEY_LEN]) -> CryptorForWriting {
        CryptorForWriting::new(Self {
            key,
        })
    }

    fn build_cipher(&self, xnonce_bytes: &[u8]) -> XChaCha20 {
        XChaCha20::new(Key::from_slice(self.key), XNonce::from_slice(xnonce_bytes))
    }
}

pub struct CryptorForReading<'a> {
    cryptor: Cryptor<'a>,
    cipher: Option<XChaCha20>,
    xnonce_bytes: Option<Vec<u8>>,
}

impl<'a> CryptorForReading<'a> {
    fn new(cryptor: Cryptor<'a>) -> Self {
        Self {
            cryptor,
            cipher: None,
            xnonce_bytes: None,
        }
    }

    /// Returns how many more bytes should be fed to [Self::input()]
    /// before the actual decryption starts
    pub fn missing_nonce_len(&self) -> usize {
        self.cipher.as_ref()
            .map(|_| 0)
            .unwrap_or_else(|| self.xnonce_bytes.as_ref()
                .map(|xnonce_bytes| NONCE_LEN - xnonce_bytes.len())
                .unwrap_or(NONCE_LEN))
    }

    /// Decrypts, in place, the `encrypted_chunk`.
    /// A slice is returned pointing to the decrypted data.
    /// It is guaranteed that the returned slice is within `encrypted_chunk`
    pub fn input<'b>(&mut self, encrypted_chunk: &'b mut [u8]) -> &'b [u8] {

        if let Some(cipher) = self.cipher.as_mut() {

            // for additional operations
            ////////////////////////////

            cipher.apply_keystream(encrypted_chunk);
            encrypted_chunk     // now, decrypted

        } else {

            // for the first operations
            ///////////////////////////
            // (before we have a full nonce)

            let chunk_nonce_length;
            let new_cipher;
            // the chunk contains the full nonce data. No need to store it in self
            if self.xnonce_bytes.is_none() && encrypted_chunk.len() >= NONCE_LEN {
                chunk_nonce_length = NONCE_LEN;
                let xnonce_bytes = &encrypted_chunk[..chunk_nonce_length];
                new_cipher = self.cryptor.build_cipher(xnonce_bytes);
            } else {
                // either nonce cannot be filled in this call or we are on a subsequent call trying to fill it
                // -- store what we have and continue from there
                let self_xnonce_bytes = self.xnonce_bytes.get_or_insert_with(|| Vec::with_capacity(NONCE_LEN));
                chunk_nonce_length = usize::min(encrypted_chunk.len(), NONCE_LEN - self_xnonce_bytes.len());
                self_xnonce_bytes
                    .extend_from_slice(&encrypted_chunk[..chunk_nonce_length]);
                // do we have the complete xnonce data to build the cipher yet?
                if self_xnonce_bytes.len() < NONCE_LEN {
                    return &[];
                }
                new_cipher =  self.cryptor.build_cipher(self_xnonce_bytes);
                _ = self.xnonce_bytes.take();
            };
            let new_cipher = self.cipher.insert(new_cipher);

            let encrypted_chunk = &mut encrypted_chunk[chunk_nonce_length..];
            new_cipher.apply_keystream(encrypted_chunk);
            encrypted_chunk     // now, decrypted
        }
    }

}

pub struct CryptorForWriting {
    cipher: XChaCha20,
    xnonce_bytes: Option<[u8; NONCE_LEN]>,
}

impl CryptorForWriting {
    fn new(cryptor: Cryptor) -> Self {
        let (cipher, xnonce_bytes) = Self::build_cipher(&cryptor);
        Self {
            cipher,
            xnonce_bytes: Some(xnonce_bytes),
        }
    }

    /// To revert the output operations provided by this struct,
    /// the header must be the first thing [CryptorForReading] will read
    pub fn take_header(&mut self) -> Option<[u8; NONCE_LEN]> {
        self.xnonce_bytes.take()
    }

    /// Encrypts -- either in place or making a new allocation -- the `plaintext` data.
    /// It is guaranteed that an allocation will only be performed on the first call,
    /// to include the header alongside the data.
    pub fn output_composed_in_place<'a>(&mut self, plain_text: &'a mut [u8]) -> Cow<'a, [u8]> {
        self.take_header()
            .map(|xnonce| {
                let mut encrypted = Vec::new();
                encrypted.reserve_exact(plain_text.len());
                encrypted.extend_from_slice(&xnonce);
                unsafe { encrypted.set_len(encrypted.len() + plain_text.len()) };
                self.cipher.apply_keystream_b2b(plain_text, &mut encrypted[NONCE_LEN..])
                    .expect("XChaCha20 reached it's size limit");
                Cow::Owned(encrypted)
            })
            .unwrap_or_else(move || {
                self.cipher.apply_keystream(plain_text);
                Cow::Borrowed(plain_text)   // now encrypted
            })
    }

    /// This function is convenient, but inefficient, as it will always allocate.
    /// If you only have read-only data, it is preferable to handle your own buffer
    /// and use [Self::output_b2b()]
    pub fn output_ro(&mut self, plain_text: &[u8]) -> Vec<u8> {
        self.take_header()
            .map(|xnonce| {
                let mut encrypted = Vec::new();
                encrypted.reserve_exact(NONCE_LEN + plain_text.len());
                encrypted.extend_from_slice(&xnonce);
                unsafe { encrypted.set_len(encrypted.len() + plain_text.len()) };
                self.cipher.apply_keystream_b2b(plain_text, &mut encrypted[NONCE_LEN..])
                    .expect("XChaCha20 reached it's size limit");
                encrypted
            })
            .unwrap_or_else(|| {
                let mut encrypted = plain_text.to_vec();
                self.cipher.apply_keystream(&mut encrypted);
                encrypted
            })
    }

    /// This function provides a considerable optimization over
    /// [Self::output_ro()] when you only have read-only data.
    /// But, by using it, you must handle the headers correctly
    /// -- via [Self::take_header()]
    pub fn output_b2b(&mut self, plain_text: &[u8], encrypted: &mut [u8]) {
           self.cipher.apply_keystream_b2b(plain_text, encrypted)
               .expect("XChaCha20 reached it's size limit");
    }

    fn build_cipher(cryptor: &Cryptor) -> (XChaCha20, [u8; NONCE_LEN]) {
        use rand::TryRngCore;
        let mut xnonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut xnonce_bytes)
            .expect("OS Random Generator seems to be misconfigured");
        let cipher = cryptor.build_cipher(&xnonce_bytes);
        (cipher, xnonce_bytes)
    }

}

// Tokio's Async Read & Write integration
/////////////////////////////////////////
use tokio::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct CryptorAsyncReader<'a, InnerAsyncReaderType> {
    inner: InnerAsyncReaderType,
    cryptor: CryptorForReading<'a>,
}

impl<'a, InnerAsyncReaderType: tokio::io::AsyncRead + Unpin> CryptorAsyncReader<'a, InnerAsyncReaderType> {
    pub fn new(inner: InnerAsyncReaderType, key: &'a [u8; 32]) -> Self {
        Self {
            inner,
            cryptor: Cryptor::for_reading(key),
        }
    }

    pub fn from_cryptor(inner: InnerAsyncReaderType, cryptor: CryptorForReading<'a>) -> Self {
        Self { inner, cryptor }
    }

}

impl<'a, InnerAsyncReaderType: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CryptorAsyncReader<'a, InnerAsyncReaderType> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        decrypted_dst: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {

        // keep trying to read the encrypted file header before anything else
        // -- every iteration may return Poll::Pending if no data is available
        loop  {
            let header_handicap = self.cryptor.missing_nonce_len();
            if header_handicap == 0 {
                break;
            }
            // optimization trick: reuse the unused portion of the user-provided `buf` to read from the `inner` AsyncRead
            let mut header_slice = decrypted_dst.take(header_handicap);
            let header_read_count = {
                match Pin::new(&mut self.inner).poll_read(cx, &mut header_slice) {
                    Poll::Ready(Ok(_)) => header_slice.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            };

            if header_read_count == 0 {
                return Poll::Ready(Ok(()));
            }


            self.cryptor.input(header_slice.filled_mut());
        }

        // read the data
        ////////////////

        // optimization trick: reuse the unused portion of the user-provided `buf` to read from the `inner` AsyncRead
        let mut encrypted_slice = decrypted_dst.take(usize::MAX);
        match Pin::new(&mut self.inner).poll_read(cx, &mut encrypted_slice) {
            Poll::Ready(Ok(_encrypted_bytes_read_count)) => (),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let encrypted_slice = encrypted_slice.filled_mut();
        let decrypted_len = self.cryptor.input(encrypted_slice).len();
        unsafe { decrypted_dst.assume_init(decrypted_len) };
        decrypted_dst.advance(decrypted_len);
        Poll::Ready(Ok(()))
    }
}

pub struct CryptorAsyncWriter<T> {
    inner: T,
    cryptor: CryptorForWriting,
    preserved_buffer: Option<Vec<u8>>,
}

impl<T: tokio::io::AsyncWrite + Unpin> CryptorAsyncWriter<T> {
    pub fn new(inner: T, key: &[u8; 32]) -> Self {
        Self {
            inner,
            cryptor: Cryptor::for_writing(key),
            preserved_buffer: None,
        }
    }

    pub fn from_cryptor(inner: T, cryptor: CryptorForWriting) -> Self {
        Self { inner, cryptor, preserved_buffer: None }
    }
}


impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CryptorAsyncWriter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        plain_text_src: &[u8],
    ) -> Poll<Result<usize>> {

        let inner_ptr = std::ptr::addr_of_mut!(self.inner);
        let cryptor_ptr = std::ptr::addr_of_mut!(self.cryptor);
        let cryptor = unsafe { &mut *cryptor_ptr };
std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        loop {
            let inner = unsafe { std::pin::Pin::new(&mut *inner_ptr) };
            // make sure we have written any other not fully written (but previously processed) buffer
            if let Some(preserved_buffer) = &mut self.preserved_buffer {
                if preserved_buffer.is_empty() {
                    // normal operation --> encrypt & try to write all of it
                    // let mut encrypted_buf = Vec::with_capacity(plain_text_buf.len());
                    let encrypted_buf = preserved_buffer;
                    // regardless of the result of the bellow downstream operation,
                    // we must report we accepted the data fully, so the same data will not
                    // come again in `plain_text_buf` in subsequent calls
                    let accepted_bytes_count = plain_text_src.len();
                    encrypted_buf.reserve(accepted_bytes_count);
                    #[allow(clippy::uninit_vec)]
                    unsafe { encrypted_buf.set_len(accepted_bytes_count) };
                    cryptor.output_b2b(plain_text_src, encrypted_buf);
                    return match inner.poll_write(cx, encrypted_buf) {
                        Poll::Ready(Ok(written_bytes_count)) => {
                            // previous buffer was written loop again and try to perform the originally asked operation
                            if written_bytes_count > 0 {
                                encrypted_buf.drain(..written_bytes_count);
                                Poll::Ready(Ok(accepted_bytes_count))
                            } else {
                                // propagates the Write Zero error upstream
                                return Poll::Ready(Ok(0));
                            }
                        },
                        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                        Poll::Pending => Poll::Ready(Ok(accepted_bytes_count)),
                    }
                } else {
                    let preserve_poll = Self::write_preserved_buffer(inner, cx, preserved_buffer);
                    match preserve_poll {
                        Poll::Ready(Ok(written_bytes_count)) => {
                            // previous buffer was written loop again and try to perform the originally asked operation
                            // unless we faced the Write Zero error
                            if written_bytes_count == 0 {
                                return Poll::Ready(Ok(0));
                            }
                        },
                        _ => return preserve_poll,
                    }
                }
            } else {
                // calling for the first time -- compute just the encryption header and loop again to write it + the rest of `plain_text_buf`
                self.preserved_buffer = cryptor.take_header().map(|xnonce| xnonce.to_vec());
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let inner_ptr = std::ptr::addr_of_mut!(self.inner);
        let mut inner = unsafe { &mut *inner_ptr };
        if let Some(preserved_buffer) = &mut self.preserved_buffer {
            if !preserved_buffer.is_empty() {
                return match Self::write_preserved_buffer(std::pin::pin!(&mut inner), cx, preserved_buffer) {
                    Poll::Ready(Ok(_written)) => std::pin::pin!(inner).poll_flush(cx),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
        std::pin::pin!(inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let inner_ptr = std::ptr::addr_of_mut!(self.inner);
        let inner = unsafe { std::pin::Pin::new(&mut *inner_ptr) };
        match self.poll_flush(cx) {
            Poll::Ready(Ok(())) => inner.poll_shutdown(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> CryptorAsyncWriter<T> {

    /// Write in full (or in part) the unwritten part of the previous (preserved) buffer.
    fn write_preserved_buffer(inner: Pin<&mut T>, cx: &mut Context<'_>, preserved_buffer: &mut Vec<u8>) -> Poll<Result<usize>> {
        match inner.poll_write(cx, preserved_buffer) {
            Poll::Ready(Ok(written_bytes_count)) => {
                preserved_buffer.drain(..written_bytes_count);
                Poll::Ready(Ok(written_bytes_count))
            },
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

}


#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;
    use super::*;

    #[test]
    fn happy_enc_dec() {
        let expected = b"Now this payload must be encrypted/decrypted, as we do provide a key to `Cryptable::new()`";
        let key = b"123456789 123456789 123456789 12";

        let mut cryptable = Cryptor::for_writing(key);
        let mut outgoing = cryptable.output_ro(expected);
        assert_ne!(
            outgoing,
            expected,
            "`output()` shouldn't return the same plain chunk"
        );

        let mut cryptable = Cryptor::for_reading(key);
        let incoming = cryptable.input(&mut outgoing);
        assert_eq!(
            incoming,
            expected,
            "`output()` => `input()` encryption/decryption round-trip didn't work"
        );
    }

    #[test]
    fn outgoing_multi_chunk() {
        let expected = b"Now this payload must also be encrypted/decrypted, but -- this time -- we will encrypt it in 2 chunks and will have it decrypted in one go. This aims to prove we can use this module to wrap outgoing IO data.";
        let cut_n = 28;
        let chunk1 = &expected[..cut_n];
        let chunk2 = &expected[cut_n..];
        let key = b"123456789 123456789 123456789 12";

        let mut cryptable = Cryptor::for_writing(key);
        let mut full_output = vec![];
        full_output.extend_from_slice(cryptable.output_ro(chunk1).as_ref());
        full_output.extend_from_slice(cryptable.output_ro(chunk2).as_ref());

        let mut cryptable = Cryptor::for_reading(key);
        let incoming = cryptable.input(&mut full_output);
        assert_eq!(
            incoming,
            expected,
            "`output()` => `input()` encryption/decryption round-trip didn't work for different chunk sizes for outgoing & incoming data"
        );
    }

    #[test]
    fn incoming_multi_chunk() {
        let expected = b"Now this payload must also be encrypted/decrypted, but -- this time -- we will encrypt it in 2 chunks and will have it decrypted in one go. This aims to prove we can use this module to wrap outgoing IO data.";
        let key = b"123456789 123456789 123456789 12";

        let mut cryptable = Cryptor::for_writing(key);
        let outgoing = cryptable.output_ro(expected);

        let cut_n = 28;
        let mut chunk1 = outgoing[..cut_n].to_vec();
        let mut chunk2 = outgoing[cut_n..].to_vec();

        let mut cryptable = Cryptor::for_reading(key);
        let mut full_input = vec![];
        full_input.extend_from_slice(cryptable.input(&mut chunk1).as_ref());
        full_input.extend_from_slice(cryptable.input(&mut chunk2).as_ref());
        assert_eq!(
            full_input, expected,
            "`output()` => `input()` encryption/decryption round-trip didn't work for different chunk sizes for outgoing & incoming data"
        );
    }

    #[test]
    fn chunked_nonce_smaller() {
        let expected = b"For this test, the first input chunk is not enough to get the nonce (less than 24 bytes). Here we assert we correctly handle this scenario";
        let key = b"123456789 123456789 123456789 12";

        let mut cryptable = Cryptor::for_writing(key);
        let outgoing = cryptable.output_ro(expected);

        let cut_n = 14;
        let mut chunk1 = outgoing[..cut_n].to_vec();
        let mut chunk2 = outgoing[cut_n..].to_vec();

        let mut cryptable = Cryptor::for_reading(key);
        let mut full_input = vec![];
        full_input.extend_from_slice(cryptable.input(&mut chunk1).as_ref());
        full_input.extend_from_slice(cryptable.input(&mut chunk2).as_ref());
        assert_eq!(
            full_input, expected,
            "`output()` => `input()` encryption/decryption round-trip didn't work when the first chunk is smaller than NONCE_LEN"
        );
    }

    #[test]
    fn chunked_nonce_exact() {
        let expected = b"For this test, the first input chunk is exactly the size of the nonce (24 bytes). Here we assert we correctly handle this scenario as well";
        let key = b"123456789 123456789 123456789 12";

        let mut cryptable = Cryptor::for_writing(key);
        let outgoing = cryptable.output_ro(expected);

        let cut_n = NONCE_LEN;
        let mut chunk1 = outgoing[..cut_n].to_vec();
        let mut chunk2 = outgoing[cut_n..].to_vec();

        let mut cryptable = Cryptor::for_reading(key);
        let mut full_input = vec![];
        full_input.extend_from_slice(cryptable.input(&mut chunk1).as_ref());
        full_input.extend_from_slice(cryptable.input(&mut chunk2).as_ref());
        assert_eq!(
            full_input, expected,
            "`output()` => `input()` encryption/decryption round-trip didn't work when the first chunk is exactly NONCE_LEN"
        );
    }

    #[tokio::test]
    async fn async_read_write() {
        let key = b"123456789 123456789 123456789 12";
        let payload = b"Hello, encrypted world!";

        // Create a mock in-memory buffer to act as our "stream"
        let mut encrypted_buffer: Vec<u8> = Vec::new();

        // Use a cursor to simulate a writeable stream
        let mut writer = CryptorAsyncWriter::new(&mut encrypted_buffer, key);
        writer.write_all(payload).await
            .expect("Couldn't write");
        writer.flush().await
            .expect("Couldn't flush");

        println!("Original:  #{}", payload.len());
        println!("Encrypted: #{}", encrypted_buffer.len());

        // Now, create a reader to read from the buffer
        let mut reader = CryptorAsyncReader::new(encrypted_buffer.as_slice(), key);
        let mut decrypted_data = Vec::new();
        reader.read_to_end(&mut decrypted_data).await
            .expect("Couldn't read");

        println!("Decrypted: #{}", decrypted_data.len());
        println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_data));
        assert_eq!(&decrypted_data, payload);
    }

    /// Assures we are able to handle empty files -- if threated as encrypted.
    /// Particularly, these files won't have our header
    #[tokio::test]
    async fn empty_encrypted_file() {
        let key = b"123456789 123456789 123456789 12";
        let encrypted_buffer: Vec<u8> = vec![];    // empty file

        let mut reader = CryptorAsyncReader::new(encrypted_buffer.as_slice(), key);
        let mut decrypted_data = Vec::new();

        let read_result = timeout(Duration::from_millis(2000), async {
            reader.read(&mut decrypted_data).await
        }).await;

        match read_result {
            Err(_timeout) => {
                panic!("Attempting to decrypt an empty file caused a hang");
            }
            Ok(Err(err)) => {
                panic!("Unexpected error: {}", err);
            }
            Ok(Ok(_n)) if _n > 0 => panic!("An encrypted, but empty file, produced -- somehow -- read results"),
            Ok(Ok(_n))/* if _n == 0*/ => println!("All good. We don't flag `UnexpectedEof` because the actual decrypted number of bytes to read is really 0"),
        }
    }

}
