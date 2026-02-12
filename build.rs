fn main() {
    let db_path = std::path::Path::new("data/p256_blocklist.bin");
    if !db_path.exists() {
        panic!(
            "Database file not found at data/p256_blocklist.bin. \
             Run 'make generate' first to create the blocklist database."
        );
    }
    println!("cargo:rerun-if-changed=data/p256_blocklist.bin");
}
