use std::io::ErrorKind;
use crate::crypto::cryptor::{CryptorAsyncReader, CryptorAsyncWriter};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io;
pub use tokio::fs::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type Key = [u8; crate::crypto::cryptor::KEY_LEN];

static mut ENCRYPTION_KEY: Option<Key> = None;

pub fn set_key(key: Key) -> Option<Key> {
    let old_key = unsafe {
        #[allow(static_mut_refs)]
        ENCRYPTION_KEY.replace(key)
    };
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    old_key
}

fn get_key() -> &'static Option<Key> {
    unsafe {
        #[allow(static_mut_refs)]
        &ENCRYPTION_KEY
    }
}

// Tokio FS API replacements
////////////////////////////

/// Encryptable replacement for [tokio::fs::read()]
pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    match get_key() {
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
    match get_key() {
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
            match get_key() {
                None => File::Plain { tokio_file: tokio::fs::File::open(path).await? },
                Some(key) => File::EncryptedReader { cryptor_async_reader: CryptorAsyncReader::new(tokio::fs::File::open(path).await?, key) }
            }
        )
    }

    /// Encryptable replacement for [tokio::fs::File::create()]
    pub async fn create(path: impl AsRef<Path>) -> io::Result<File> {
        Ok(
            match get_key() {
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