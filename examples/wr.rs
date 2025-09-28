//! Simple Write & Read example


#[tokio::main]
async fn main() {
    use encryptable_tokio_fs::fs;
    const CONTENTS: &[u8] = b"Congrats! The contents had been successfully written and read back! Now go and inspect the actual file contents!";
    const FILE: &str = "/tmp/wr.file";

    // comment/uncomment to see the file being written in plain/encrypted modes
    fs::set_key(*b"123456789 123456789 123456789 12");

    fs::write(FILE, CONTENTS).await
        .expect("Failed to write to file");

    let contents = fs::read(FILE).await
        .expect("Failed to read from file");

    println!("{}", String::from_utf8_lossy(&contents));

}