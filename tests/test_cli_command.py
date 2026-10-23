"""Offline CLI regression tests."""
from unittest.mock import patch
import ssl
from click.testing import CliRunner
from sslchecker.cli import cli
from sslchecker.sslcert import SSLCert


def test_successful_certificate():
    from pathlib import Path
    cert = SSLCert.from_pem((Path(__file__).parent / "inode_cert.txt").read_bytes())
    # Rendering a historical certificate should work even when it is expired.
    with patch("sslchecker.cli.get_sslcert", return_value=cert):
        result = CliRunner().invoke(cli, ["example.com"])
    assert result.exit_code == 0
    assert "Common name:" in result.output


def test_invalid_certificate():
    with patch("sslchecker.cli.get_sslcert", side_effect=ssl.SSLCertVerificationError("untrusted")):
        result = CliRunner().invoke(cli, ["invalid.example"])
    assert result.exit_code != 0
    assert "TLS verification failed" in result.output


def test_timeout():
    with patch("sslchecker.cli.get_sslcert", side_effect=TimeoutError("timeout")):
        result = CliRunner().invoke(cli, ["example.com", "--timeout", "1"])
    assert result.exit_code != 0
