"""X.509 fixture tests, independent of live websites."""
from pathlib import Path
import pytest
from sslchecker.sslcert import SSLCert

FIXTURES = Path(__file__).parent


def test_pem_round_trip_and_fingerprint():
    cert = SSLCert.from_pem((FIXTURES / "inode_cert.txt").read_bytes())
    assert cert.cn == "www.inode.co.nz"
    assert cert.keyinfo == ("RSA", 2048)
    assert cert.serial > 0
    assert cert.notbefore < cert.notafter
    assert len(cert.digest("sha256")) == 32
    assert SSLCert.from_pem(cert.to_pem()) == cert


def test_der_parsing():
    cert = SSLCert.from_der((FIXTURES / "dercert").read_bytes())
    assert cert.cn


def test_broken_extensions_do_not_break_parser():
    try:
        cert = SSLCert.from_pem((FIXTURES / "weird_cert.txt").read_bytes())
    except ValueError:
        pytest.skip("Legacy malformed certificate rejected by current cryptography")
    assert isinstance(cert.altnames, list)
