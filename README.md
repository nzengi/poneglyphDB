# PoneglyphDB

A production-ready implementation of efficient non-interactive zero-knowledge proofs for arbitrary SQL query verification. PoneglyphDB enables database owners to prove the correctness of SQL query results without revealing the underlying data, addressing critical privacy and verifiability challenges in modern data systems.

## Introduction

Traditional database systems face a fundamental tension between privacy and verifiability. Database owners want to keep their data confidential, while query clients need assurance that results are computed correctly. PoneglyphDB solves this problem by leveraging zero-knowledge proof (ZKP) technology to generate cryptographic proofs that verify query correctness without exposing sensitive information.

This implementation is based on PLONKish-based arithmetic circuits, custom gate optimizations, and recursive proof composition techniques to achieve practical performance for real-world SQL workloads.

## Key Features

**Zero-Knowledge Guarantees**: Database contents remain completely private throughout the query execution and proof generation process. Only the query result and its proof are revealed to clients.

**Non-Interactive Proofs**: Unlike interactive ZKP systems, PoneglyphDB generates self-contained proofs that can be verified offline by anyone with the verification key. This enables proof caching, transferability, and asynchronous verification.

**Arbitrary SQL Support**: The system handles complex SQL queries including:

- Selection and projection operations
- Various join types (INNER, LEFT, RIGHT, FULL)
- Aggregation functions (SUM, COUNT, AVG, MAX, MIN)
- GROUP BY and ORDER BY clauses
- Window functions (ROW_NUMBER, RANK, LAG)
- Subqueries and nested queries
- LIMIT clauses

**Performance Optimizations**: Multiple optimization techniques ensure practical performance:

- Custom gates for common SQL operations reduce circuit size
- Lookup tables (Plookup) optimize range checks and comparisons
- Recursive proof composition handles large queries efficiently
- Parallel witness computation and batch operations
- Query-specific optimizations (index-based, predicate pushdown)

## Getting Started

### Prerequisites

- Rust 1.70 or later (managed via `rust-toolchain.toml`)
- PostgreSQL (for database integration)
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/poneglyphdb.git
cd poneglyphdb

# Install git hooks (optional but recommended)
make install-hooks
# or
cargo husky install

# Build all workspace crates
cargo build --release
# or
make release

# Run the test suite
cargo test
# or
make test

# Run benchmarks
cargo bench
# or
make bench

# Generate code coverage
make coverage

# Check code quality
make check
```

### Quick Commands

We provide a `Makefile` with common development tasks:

```bash
make help          # Show all available commands
make install-hooks # Install git pre-commit hooks
make test          # Run all tests
make fmt           # Format code
make clippy        # Run clippy linter
make check         # Run all checks (fmt, clippy, test)
make coverage      # Generate code coverage report
make bench         # Run benchmarks
make docs          # Build and open documentation
make ci            # Run CI checks locally
```

### Git Hooks

Pre-commit hooks automatically run:

- Code formatting check
- Clippy linting
- Test suite

Install hooks:

```bash
make install-hooks
```

### Code Coverage

Code coverage is tracked via Codecov. View coverage reports in:

- GitHub Actions artifacts
- Codecov dashboard (when configured)

### Performance Tracking

Benchmark results are tracked over time using `criterion-trend`. Results are uploaded as GitHub Actions artifacts.

### Documentation

- API documentation: `cargo doc --open`
- Online: [docs.rs/poneglyphdb-core](https://docs.rs/poneglyphdb-core) (when published)
- Local: `make docs`

## Security Considerations

- **Trusted Setup**: The system requires a one-time trusted setup ceremony to generate public parameters. The setup is transparent and can be audited.

- **Zero-Knowledge**: The proofs reveal no information about database contents beyond what is explicitly in the query result.

- **Soundness**: Proofs are cryptographically secure and cannot be forged without breaking the underlying cryptographic assumptions.

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) and code of conduct before submitting pull requests.

## Citation

If you use PoneglyphDB in your research, please cite:

```
PoneglyphDB: Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification
https://arxiv.org/pdf/2411.15031
```

## Acknowledgments

This implementation is based on the research paper "PoneglyphDB: Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification". We thank the authors for their groundbreaking work in verifiable database systems.
