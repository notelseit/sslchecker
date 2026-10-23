SSL Checker
===========

Modern SSL/TLS certificate checker for Python 3.13 and later.

Current documentation: README.md

Install from this repository::

    python -m pip install .

Run::

    sslchecker example.com
    sslchecker https://example.com:443 --timeout 10

SSL Checker validates certificate trust and hostnames using Python's ssl module.
The original project and attribution are retained in the repository history and license.
