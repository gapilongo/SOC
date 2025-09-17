# Contributing to LG-SOTF

Thank you for your interest in contributing! We welcome all contributions from bug reports to new features.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Run tests: `python scripts/run_tests.py`
5. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/gapilongo/SOC.git
cd lg-sotf

# Install dependencies
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run tests to verify setup
python -m pytest tests/
```

## Code Guidelines

- Follow PEP 8 style guidelines
- Add tests for new functionality
- Update documentation when needed
- Keep commits focused and atomic
- Write clear commit messages

## Code Quality

We use automated tools to maintain code quality:
- **Black** for formatting
- **isort** for import sorting  
- **flake8** for linting
- **mypy** for type checking

Run before submitting:
```bash
pre-commit run --all-files
```

## Pull Request Process

1. Ensure tests pass and code follows style guidelines
2. Update documentation for new features
3. Reference any related issues in your PR description
4. Keep PRs focused on a single feature or bug fix

## Reporting Issues

When reporting bugs, please include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details

## Questions?

- Check existing [issues](https://github.com/gapilongo/SOC/issues)
- Start a [discussion](https://github.com/gapilongo/SOC/discussions)
- Review our [documentation](docs/)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
