.PHONY: help test fmt clippy clean install-hooks coverage bench docs release

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install-hooks: ## Install git hooks manually
	@echo "Installing git hooks..."
	@if [ -d .git ]; then \
		mkdir -p .git/hooks; \
		cp .husky/pre-commit .git/hooks/pre-commit 2>/dev/null || true; \
		cp .husky/pre-push .git/hooks/pre-push 2>/dev/null || true; \
		chmod +x .git/hooks/pre-commit .git/hooks/pre-push 2>/dev/null || true; \
		echo "Git hooks installed successfully!"; \
	else \
		echo "Not a git repository. Run 'git init' first."; \
	fi

test: ## Run all tests
	cargo test --workspace --all-features

test-verbose: ## Run tests with output
	cargo test --workspace --all-features -- --nocapture

fmt: ## Format code
	cargo fmt --all

fmt-check: ## Check code formatting
	cargo fmt --all -- --check

clippy: ## Run clippy
	cargo clippy --workspace --all-features -- -D warnings

clean: ## Clean build artifacts
	cargo clean

coverage: ## Generate code coverage report
	@echo "Installing cargo-tarpaulin if needed..."
	@cargo install cargo-tarpaulin --quiet 2>/dev/null || echo "cargo-tarpaulin already installed or install manually: cargo install cargo-tarpaulin"
	cargo tarpaulin --workspace --all-features --out Html --output-dir coverage/ || echo "Note: Install tarpaulin with: cargo install cargo-tarpaulin"

coverage-xml: ## Generate code coverage in XML format
	@echo "Installing cargo-tarpaulin if needed..."
	@cargo install cargo-tarpaulin --quiet 2>/dev/null || echo "cargo-tarpaulin already installed or install manually: cargo install cargo-tarpaulin"
	cargo tarpaulin --workspace --all-features --out Xml --output-dir coverage/ || echo "Note: Install tarpaulin with: cargo install cargo-tarpaulin"

bench: ## Run benchmarks
	cargo bench --workspace --all-features

bench-trend: ## Track benchmark trends
	cargo bench --workspace --all-features
	@echo "Installing criterion-trend if needed..."
	@cargo install criterion-trend --quiet 2>/dev/null || echo "criterion-trend already installed or install manually: cargo install criterion-trend"
	criterion-trend --output-dir benchmark-trends/ || echo "Note: Install criterion-trend with: cargo install criterion-trend"

docs: ## Build documentation
	cargo doc --workspace --all-features --no-deps --open

docs-check: ## Check documentation links
	cargo doc --workspace --all-features --no-deps --document-private-items

check: fmt-check clippy test ## Run all checks (fmt, clippy, test)

ci: check coverage-xml ## Run CI checks locally

release: ## Build release binaries
	cargo build --release --workspace

release-check: ## Check if ready for release
	@echo "Checking release readiness..."
	cargo fmt --all -- --check
	cargo clippy --workspace --all-features -- -D warnings
	cargo test --workspace --all-features
	cargo doc --workspace --all-features --no-deps
	@echo "Release checks passed!"

