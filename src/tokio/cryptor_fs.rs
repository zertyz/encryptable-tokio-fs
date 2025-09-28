use crate::crypto::cryptor::Cryptor;
use std::io;
use std::path::Path;

pub type Key = [u8; crate::crypto::cryptor::KEY_LEN];

#[derive(zeroize::ZeroizeOnDrop)]
pub struct CryptorFs {
    key: Key,
}

impl CryptorFs {



    // /// Encrypted replacement for [tokio::fs::read()]
    // pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    //     match crate::tokio::encryptable_fs::get_key() {
    //         None => tokio::fs::read(path).await,
    //         Some(key) => {},
    //     }
    // }

}
