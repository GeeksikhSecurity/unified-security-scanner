# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in the Unified Security Scanner, please report it privately.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: **security@unified-scanner.dev**

Include the following information:
- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Critical issues within 30 days, others within 90 days

### Security Updates

Security updates will be released as patch versions and announced through:
- GitHub Security Advisories
- Release notes
- npm security advisories (if applicable)

## Security Best Practices

When using the Unified Security Scanner:

1. **Keep Updated**: Always use the latest version
2. **Secure Configuration**: Review `.securityrc.json` settings
3. **Access Control**: Limit scanner execution to authorized users
4. **Output Security**: Secure scan reports containing sensitive findings
5. **Network Security**: Use HTTPS for remote rule downloads

## Scope

This security policy applies to:
- Core scanner engine (`packages/core/`)
- CLI interface (`packages/cli/`)
- Security rules (`rules/`)
- Documentation and examples

Out of scope:
- Third-party dependencies (report to respective maintainers)
- User-provided custom rules or configurations