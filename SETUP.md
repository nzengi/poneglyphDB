# Development Setup Guide

## Prerequisites

- Rust 1.70 or later (automatically managed via `rust-toolchain.toml`)
- Git
- PostgreSQL (for database integration)

## Initial Setup

### 1. Install Rust Toolchain

The project uses `rust-toolchain.toml` to automatically manage the Rust version:

```bash
# Rust will be automatically installed/updated when you run cargo commands
cargo --version
```

### 2. Install Development Tools

```bash
# Install cargo-husky for git hooks
cargo install cargo-husky

# Install cargo-tarpaulin for code coverage
cargo install cargo-tarpaulin

# Install criterion-trend for benchmark tracking (optional)
cargo install criterion-trend
```

### 3. Install Git Hooks

```bash
make install-hooks
# or manually:
cargo husky install
```

This will set up pre-commit and pre-push hooks that automatically:

- Format code
- Run clippy
- Run tests

### 4. Verify Setup

```bash
# Run all checks
make check

# Build the project
make release

# Run tests
make test
```

## Common Issues and Solutions

### Issue: `cargo husky install` fails

**Solution:**

```bash
# Install cargo-husky first
cargo install cargo-husky
# Then install hooks
cargo husky install
```

### Issue: `cargo tarpaulin` not found

**Solution:**

```bash
cargo install cargo-tarpaulin
```

### Issue: `cargo fmt` warnings about unstable features

**Solution:**
The project uses stable Rust. Some formatting options in `.rustfmt.toml` are commented out because they require nightly Rust. This is expected and safe to ignore.

### Issue: `jobs = 0` error in `.cargo/config.toml`

**Solution:**
This has been fixed. Cargo now auto-detects the number of CPU cores by default.

### Issue: Formatting differences

**Solution:**

```bash
# Auto-format all code
make fmt

# Then commit
git add .
git commit -m "Format code"
```

## Development Workflow

1. **Create a branch:**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes and test:**

   ```bash
   make test
   make clippy
   ```

3. **Format code before committing:**

   ```bash
   make fmt
   ```

4. **Commit (hooks will run automatically):**

   ```bash
   git commit -m "Your commit message"
   ```

5. **Push (pre-push hooks will run):**
   ```bash
   git push
   ```

## Useful Commands

```bash
make help          # Show all available commands
make test          # Run all tests
make fmt           # Format code
make clippy        # Run linter
make check         # Run all checks
make coverage      # Generate coverage report
make bench         # Run benchmarks
make docs          # Build documentation
make ci            # Run CI checks locally
```

## IDE Setup

### VS Code

Recommended extensions:

- `rust-analyzer` - Rust language support
- `CodeLLDB` - Debugging support

### IntelliJ / CLion

- Install the Rust plugin
- Configure Rust toolchain to use the project's `rust-toolchain.toml`

## Troubleshooting

### Clear build cache

```bash
make clean
cargo clean
```

### Update dependencies

```bash
cargo update
```

### Check Rust version

```bash
rustc --version
cargo --version
```

### Verify toolchain

```bash
rustup show
```
