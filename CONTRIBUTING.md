# Contributing to PoneglyphDB

Thank you for your interest in contributing to PoneglyphDB! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/nzengi/poneglyphDB`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Ensure tests pass: `cargo test --workspace`
6. Ensure code is formatted: `cargo fmt --all`
7. Ensure clippy passes: `cargo clippy --workspace -- -D warnings`
8. Commit your changes: `git commit -m "Add your feature"`
9. Push to your fork: `git push origin feature/your-feature-name`
10. Open a Pull Request

## Development Workflow

### Prerequisites

- Rust 1.70 or later (managed via `rust-toolchain.toml`)
- PostgreSQL (for database integration)
- Git

### Building

```bash
# Build all crates
cargo build --workspace

# Build in release mode
cargo build --release --workspace
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p poneglyphdb-core

# Run tests with output
cargo test --workspace -- --nocapture
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Run clippy
cargo clippy --workspace --all-features -- -D warnings

# Check formatting
cargo fmt --check --all
```

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` to format code
- Follow clippy suggestions (configured in `.clippy.toml`)
- Document all public APIs with doc comments

### Commit Messages

- Use clear, descriptive commit messages
- Start with a capital letter
- Use imperative mood ("Add feature" not "Added feature")
- Reference issues when applicable: "Fix #123"

### Code Documentation

- All public functions, types, and modules must have doc comments
- Use `///` for public documentation
- Include examples in doc comments when helpful
- Document error conditions and panics

## Pull Request Process

1. **Update Documentation**: If you're adding features, update relevant documentation
2. **Add Tests**: New features should include tests
3. **Update CHANGELOG**: Add an entry to `CHANGELOG.md` describing your changes
4. **Ensure CI Passes**: All CI checks must pass before merge
5. **Request Review**: Request review from maintainers

### PR Checklist

- [ ] Code follows the project's style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests pass locally
- [ ] CHANGELOG.md updated
- [ ] No new warnings introduced

## Project Structure

- `poneglyphdb-core/`: Core library with ZKP implementation
- `poneglyphdb-host/`: Host server
- `poneglyphdb-client/`: Client library
- `poneglyphdb-cli/`: CLI tool
- `tests/`: Integration tests
- `benches/`: Performance benchmarks
- `examples/`: Example code
- `docs/`: Additional documentation

## Areas for Contribution

- Bug fixes
- Performance improvements
- Documentation improvements
- New features (discuss in issues first)
- Test coverage improvements
- Benchmark optimizations

## Questions?

Feel free to open an issue for questions or discussions about contributions.

