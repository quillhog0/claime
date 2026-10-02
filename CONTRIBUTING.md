# Contributing to Claime

We welcome contributions to Claime. To keep the codebase secure, deterministic, and clean, please follow these guidelines.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/quillhog0/claime.git
   cd claime
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pyflakes pip-audit
   ```

## Running Tests & Linters

Before submitting a Pull Request, ensure that all checks pass:

```bash
# 1. Lint check (must pass with zero errors)
python -m pyflakes *.py tests/*.py

# 2. Run automated test suite
python -m pytest -q

# 3. Dependency vulnerability audit
pip-audit -r requirements.txt
```

## Commit Message Guidelines

We follow conventional commits:
- `feat:` for new features
- `fix:` for bug fixes
- `refactor:` for code changes that neither fix a bug nor add a feature
- `test:` for adding or correcting tests
- `docs:` for documentation changes

## Submitting Pull Requests

1. Fork the repo and create your branch from `main`.
2. Ensure test coverage for any new features or bug fixes.
3. Open a Pull Request filling out the PR template completely.
