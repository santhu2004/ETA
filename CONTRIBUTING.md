# Contributing to Encrypted Traffic Analysis System

Thank you for your interest in contributing to the Encrypted Traffic Analysis System! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites
- Python 3.7 or higher
- Git
- Basic understanding of network security concepts

### Setup Development Environment
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/encrypted-traffic-analysis.git`
3. Create a virtual environment: `python -m venv venv`
4. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
5. Install dependencies: `pip install -r requirements.txt`
6. Install development dependencies: `pip install -r requirements.txt[dev]`

## 🏗️ Project Structure

```
encrypted-traffic-analysis/
├── attacker_sim/     # Attack simulation and testing
├── cli/             # Command-line interface
├── core/            # Core analysis engine
├── dashboard/       # Future web interface (Django + React)
├── rules/           # Threat intelligence rules
├── tests/           # Unit tests
├── config.yaml      # Configuration file
├── requirements.txt # Python dependencies
└── README.md        # Project documentation
```

## 🔧 Development Guidelines

### Code Style
- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Add comprehensive docstrings to all functions and classes
- Keep functions focused and single-purpose
- Use meaningful variable and function names

### Testing
- Write unit tests for all new functionality
- Ensure all tests pass before submitting a PR
- Aim for at least 80% code coverage
- Test both positive and negative cases

### Documentation
- Update README.md for new features
- Add inline comments for complex logic
- Document any configuration changes
- Include usage examples

## 🚀 Adding New Features

### 1. Threat Detection Rules
To add new detection rules:

1. **Extend the Analyzer class** in `core/analysis.py`:
```python
def _check_new_threat(self, packet_data: Dict) -> Optional[Tuple[str, str]]:
    """Check for new threat pattern."""
    # Implementation here
    return None
```

2. **Add to the checks list** in the `analyze` method
3. **Update confidence calculation** if needed
4. **Add tests** in `tests/test_analysis.py`

### 2. New Capture Engines
To add new packet capture engines:

1. **Create new engine class** in `core/capture.py`
2. **Implement required methods**: `start_capture()`, `stop_capture()`, `get_packet()`
3. **Add to factory function** `get_capture_engine()`
4. **Add tests** for the new engine

### 3. New Mitigation Actions
To add new mitigation actions:

1. **Extend the Mitigator class** in `core/mitigation.py`
2. **Implement action methods**
3. **Add configuration options** to `config.yaml`
4. **Update CLI commands** in `cli/main.py`

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=core tests/

# Run specific test file
python -m pytest tests/test_analysis.py

# Run tests with verbose output
python -m pytest -v tests/
```

### Test Structure
- Unit tests for individual functions
- Integration tests for component interactions
- Mock external dependencies (network, filesystem)
- Use fixtures for common test data

## 📝 Pull Request Process

1. **Create a feature branch** from `main`
2. **Make your changes** following the guidelines above
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Ensure all tests pass**
6. **Submit a pull request** with a clear description

### PR Description Template
```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🐛 Reporting Issues

When reporting issues, please include:

- **Operating system** and version
- **Python version**
- **Error messages** and stack traces
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Configuration files** (sanitized)

## 📚 Resources

- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Type Hints Documentation](https://docs.python.org/3/library/typing.html)
- [Pytest Documentation](https://docs.pytest.org/)
- [Network Security Concepts](https://en.wikipedia.org/wiki/Network_security)

## 🤝 Community

- **Discussions**: Use GitHub Discussions for questions and ideas
- **Issues**: Report bugs and feature requests
- **Code Review**: Participate in reviewing other contributions
- **Documentation**: Help improve documentation and examples

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to the Encrypted Traffic Analysis System! 🎉
