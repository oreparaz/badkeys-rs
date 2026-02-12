.PHONY: generate verify build test clean

SCRIPTS_DIR := scripts
DATA_DIR := data
DB_FILE := $(DATA_DIR)/p256_blocklist.bin

# Generate the blocklist database from source repositories
generate:
	python3 $(SCRIPTS_DIR)/generate_blocklist.py --output $(DB_FILE)

# Verify the generated database
verify: $(DB_FILE)
	python3 $(SCRIPTS_DIR)/verify_blocklist.py $(DB_FILE)

# Build the Rust crate (requires database to exist)
build: $(DB_FILE)
	cargo build

# Run tests
test: $(DB_FILE)
	cargo test

# Clean generated artifacts
clean:
	rm -f $(DB_FILE)
	cargo clean
