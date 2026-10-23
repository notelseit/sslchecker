# Changelog

## 0.2.0 — Modern Python support

- Python 3.13, 3.14 and 3.15 CI matrix.
- Migrated X.509 parsing to cryptography and TLS verification to the standard ssl module.
- Added hostname and certificate trust validation.
- Updated packaging to pyproject.toml and wheel builds.
- Replaced network-dependent legacy tests with deterministic offline regressions.
- Removed legacy Travis CI and Python 2 Tox environments.
