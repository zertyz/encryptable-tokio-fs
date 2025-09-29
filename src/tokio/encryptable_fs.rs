use std::io::ErrorKind;
use crate::crypto::cryptor::KEY_LEN;
use crate::crypto::cryptor::{CryptorAsyncReader, CryptorAsyncWriter};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use sha2::{Digest, Sha256};
use tokio::io;
pub use tokio::fs::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type ChaCha20Key = [u8; KEY_LEN];

pub struct EncryptionKeys {
    content_key: ChaCha20Key,
    _path_key: ChaCha20Key,
}

static mut ENCRYPTION_KEYS: Option<EncryptionKeys> = None;

pub fn set_keys(keys: EncryptionKeys) -> Option<EncryptionKeys> {
    let old_keys = unsafe {
        #[allow(static_mut_refs)]
        ENCRYPTION_KEYS.replace(keys)
    };
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    old_keys

}

pub fn set_keys_from_passphrase(passphrase: &str) {

    assert!(passphrase.as_bytes().len() >= KEY_LEN, "`passphrase` needs to be no less than {KEY_LEN} bytes");

    let key = derive_key(passphrase.as_bytes());
    let derived_key = derive_key(key.as_ref());
    set_keys(EncryptionKeys {
        content_key: key,
        _path_key: derived_key,
    });
}

pub fn set_keys_from_base(key: ChaCha20Key) {
    let derived_key = derive_key(key.as_ref());
    set_keys(EncryptionKeys {
        content_key: key,
        _path_key: derived_key,
    });
}

fn get_content_key() -> Option<&'static ChaCha20Key> {
    unsafe {
        #[allow(static_mut_refs)]
        ENCRYPTION_KEYS.as_ref().map(|keys| &keys.content_key)
    }
}

fn derive_key(key: &[u8]) -> ChaCha20Key {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let hash_result = hasher.finalize();
    hash_result.into()
}

// Tokio FS API replacements
////////////////////////////

/// Encryptable replacement for [tokio::fs::read()]
pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    match get_content_key() {
        None => tokio::fs::read(path).await,
        Some(_key) => {
            let file = File::open(path).await?;
            let mut reader = io::BufReader::new(file);
            let mut contents = Vec::new();
            reader.read_to_end(&mut contents).await?;
            Ok(contents)
        },
    }
}

/// Encryptable replacement for [tokio::fs::write()]
pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    match get_content_key() {
        None => tokio::fs::write(path, contents).await,
        Some(_key) => {
            let file = File::create(path).await?;
            let mut writer = io::BufWriter::new(file);
            writer.write_all(contents.as_ref()).await?;
            writer.shutdown().await?;
            Ok(())
        },
    }
}

/// Encryptable replacement for [tokio::fs::File]
pub enum File {
    Plain { tokio_file: tokio::fs::File },
    EncryptedReader { cryptor_async_reader: CryptorAsyncReader<'static, tokio::fs::File> },
    EncryptedWriter { cryptor_async_writer: CryptorAsyncWriter<tokio::fs::File> },
}

impl File {

    /// Encryptable replacement for [tokio::fs::File::open()]
    pub async fn open(path: impl AsRef<Path>) -> io::Result<File> {
        Ok(
            match get_content_key() {
                None => File::Plain { tokio_file: tokio::fs::File::open(path).await? },
                Some(key) => File::EncryptedReader { cryptor_async_reader: CryptorAsyncReader::new(tokio::fs::File::open(path).await?, key) }
            }
        )
    }

    /// Encryptable replacement for [tokio::fs::File::create()]
    pub async fn create(path: impl AsRef<Path>) -> io::Result<File> {
        Ok(
            match get_content_key() {
                None => File::Plain { tokio_file: tokio::fs::File::create(path).await? },
                Some(key) => File::EncryptedWriter { cryptor_async_writer: CryptorAsyncWriter::new(tokio::fs::File::create(path).await?, key) }
            }
        )
    }

}

impl io::AsyncRead for File {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain { tokio_file } => std::pin::pin!(tokio_file).poll_read(cx, dst),
            Self::EncryptedReader { cryptor_async_reader } => std::pin::pin!(cryptor_async_reader).poll_read(cx, dst),
            File::EncryptedWriter { .. } => Poll::Ready(Err(io::Error::new(ErrorKind::Unsupported, "Attempted to read from a file opened exclusively for writing"))),
        }
    }
}

impl io::AsyncWrite for File {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain { tokio_file } => std::pin::pin!(tokio_file).poll_write(cx, src),
            File::EncryptedWriter { cryptor_async_writer } => std::pin::pin!(cryptor_async_writer).poll_write(cx, src),
            Self::EncryptedReader { .. } => Poll::Ready(Err(io::Error::new(ErrorKind::Unsupported, "Attempted to write on a file opened exclusively for reading"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Plain { tokio_file } => std::pin::pin!(tokio_file).poll_flush(cx),
            File::EncryptedWriter { cryptor_async_writer } => std::pin::pin!(cryptor_async_writer).poll_flush(cx),
            Self::EncryptedReader { .. } => Poll::Ready(Err(io::Error::new(ErrorKind::Unsupported, "Attempted to write (flush) a file opened exclusively for reading"))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Plain { tokio_file } => std::pin::pin!(tokio_file).poll_shutdown(cx),
            File::EncryptedWriter { cryptor_async_writer } => std::pin::pin!(cryptor_async_writer).poll_shutdown(cx),
            Self::EncryptedReader { .. } => Poll::Ready(Err(io::Error::new(ErrorKind::Unsupported, "Attempted to write (shutdown) on a file opened exclusively for reading"))),
        }
    }

}