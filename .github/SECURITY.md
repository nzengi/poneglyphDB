# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not** open a public issue. Instead, please report it via one of the following methods:

1. **Email**: Send details to [howyaniii@gmail.com] (replace with actual email)
2. **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### Response Time

We aim to:

- Acknowledge receipt within 48 hours
- Provide an initial assessment within 7 days
- Keep you informed of progress regularly

### Disclosure Policy

- We will work with you to understand and resolve the issue
- We will not disclose the vulnerability publicly until a fix is available
- We will credit you for the discovery (if desired)

## Security Best Practices

When using PoneglyphDB:

1. **Trusted Setup**: Ensure the trusted setup ceremony is performed correctly
2. **Key Management**: Protect your verification keys
3. **Network Security**: Use TLS/SSL for all network communications
4. **Dependencies**: Keep dependencies up to date
5. **Auditing**: Regularly audit your deployment

## Known Security Considerations

- **Trusted Setup**: The system requires a one-time trusted setup. If the setup is compromised, all proofs are invalid.
- **Key Management**: Verification keys must be kept secure and authentic.
- **Zero-Knowledge**: While proofs are zero-knowledge, query results are not. Be mindful of what information is revealed.
