//! Simple Write & Read example

// should you ever need to place a key inside the program, at least use `litcrypt`
// -- e.g., to load a configuration file where the real key is stored.
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

#[tokio::main]
async fn main() {
    use encryptable_tokio_fs::fs;
    const FILE: &str = "/tmp/wr.file";
    let contents = format!("Congrats! The contents had been successfully written and read back! Now go and inspect the actual file contents of '{FILE}'");

    // comment/uncomment to see the file being written in plain/encrypted modes
    fs::set_keys_from_passphrase(lc!("123456789 123456789 123456789 12").as_ref());

    fs::write(FILE, contents).await
        .expect("Failed to write to file");

    let contents = fs::read(FILE).await
        .expect("Failed to read from file");

    println!("{}", String::from_utf8_lossy(&contents));

}