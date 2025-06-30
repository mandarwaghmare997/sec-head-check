# Contributing to sec-head-check

Thank you for your interest in contributing to sec-head-check! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/vulnuris/sec-head-check/issues)
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Check [Issues](https://github.com/vulnuris/sec-head-check/issues) for existing feature requests
2. Create a new issue with:
   - Clear description of the feature
   - Use case and benefits
   - Possible implementation approach

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `python -m pytest tests/`
6. Update documentation if needed
7. Commit with clear messages
8. Push to your fork
9. Create a Pull Request

## Development Setup

```bash
git clone https://github.com/vulnuris/sec-head-check.git
cd sec-head-check
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Keep functions focused and small

## Testing

- Write tests for new features
- Ensure existing tests pass
- Aim for good test coverage

## Documentation

- Update README.md for new features
- Add docstrings to new functions
- Update help text for new CLI options

## Security Headers to Consider Adding

If you want to contribute new security headers, consider these:
- `Expect-CT`
- `Public-Key-Pins` (deprecated but still used)
- `Feature-Policy` (predecessor to Permissions-Policy)
- Custom security headers used by CDNs

## Questions?

Feel free to reach out:
- Create an issue for questions
- Email: contact@vulnuris.com
- Website: [vulnuris.com](https://vulnuris.com)

Thank you for contributing! 🙏

