# Contributing to Unified Security Scanner

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

### Prerequisites
- Node.js 18+ 
- pnpm 8+
- Git

### Quick Start
```bash
git clone https://github.com/yourusername/unified-security-scanner.git
cd unified-security-scanner
pnpm install
pnpm build
pnpm test
```

### Project Structure
```
packages/
├── core/           # Scanning engine
│   ├── src/
│   │   ├── orchestrator/   # Main scanner coordination
│   │   ├── adapters/       # Tool integrations (TruffleHog, Semgrep)
│   │   ├── analyzers/      # Custom scanners (malicious packages, tech debt)
│   │   ├── reporters/      # Output formats (SARIF, JSON, HTML)
│   │   └── fp-reducer/     # False positive reduction
│   └── tests/
└── cli/            # Command-line interface
    ├── src/commands/
    └── tests/
```

## Contributing Guidelines

### Adding New Scanner Integrations

1. Create adapter in `packages/core/src/adapters/`
2. Implement `ScannerAdapter` interface
3. Add configuration options to types
4. Write comprehensive tests
5. Update documentation

Example adapter structure:
```typescript
export class NewScannerAdapter implements ScannerAdapter {
  async scan(config: ScanConfig): Promise<Finding[]> {
    // Implementation
  }
}
```

### Adding Custom Security Rules

1. Create rule files in `rules/` directory
2. Follow Semgrep YAML syntax
3. Include test cases
4. Document rule purpose and examples

### Reducing False Positives

1. Add patterns to `fp-reducer/rule-engine.ts`
2. Test against real codebases
3. Document suppression logic
4. Maintain <5% false positive rate

## Testing

### Running Tests
```bash
# All tests
pnpm test

# With coverage
pnpm test:coverage

# Watch mode
pnpm test:watch

# Specific package
pnpm --filter @unified-scanner/core test
```

### Test Requirements
- Unit tests for all new features
- Integration tests for adapters
- False positive regression tests
- Minimum 90% code coverage

## Code Standards

### TypeScript
- Strict mode enabled
- Explicit return types for public methods
- Comprehensive JSDoc comments
- ESLint + Prettier formatting

### Commits
- Conventional Commits format
- Clear, descriptive messages
- Atomic commits (one feature/fix per commit)

Example:
```
feat(adapters): add Bandit Python scanner integration

- Implement BanditAdapter with ScannerAdapter interface
- Add Python-specific vulnerability detection
- Include configuration options for custom rules
- Add comprehensive test suite

Closes #123
```

## Pull Request Process

1. **Fork & Branch**: Create feature branch from `main`
2. **Develop**: Implement changes with tests
3. **Test**: Ensure all tests pass and coverage maintained
4. **Document**: Update README/docs if needed
5. **PR**: Submit with clear description and examples
6. **Review**: Address feedback and iterate
7. **Merge**: Squash merge after approval

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings/errors
```

## Release Process

Releases are automated via GitHub Actions:

1. **Version Bump**: Update package.json versions
2. **Changelog**: Update CHANGELOG.md
3. **Tag**: Create git tag (v1.2.3)
4. **CI/CD**: Automated build, test, and publish
5. **GitHub Release**: Auto-generated with changelog

## Getting Help

- **Issues**: GitHub Issues for bugs and feature requests
- **Discussions**: GitHub Discussions for questions
- **Discord**: [Community Discord](https://discord.gg/unified-scanner)
- **Email**: dev@unified-scanner.dev

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Please read and follow it in all interactions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.