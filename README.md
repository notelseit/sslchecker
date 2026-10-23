# SSL Checker

Modernized SSL/TLS certificate checker supporting Python 3.13, 3.14 and 3.15.

## Installation

```sh
python -m pip install .
```

## Usage

```sh
sslchecker example.com
sslchecker https://example.com:443 --timeout 10
```

Certificates are validated using the operating system's trust store and hostname checking. An invalid certificate or unreachable domain results in a nonzero exit code.

## Tests

```sh
python -m pip install ".[test]"
pytest tests/test_modern.py
```

This update replaces legacy netlib / pyOpenSSL parsing with cryptography and Python's standard ssl module. Original MIT license and attribution are preserved.
