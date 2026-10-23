import socket
import ssl
from unittest.mock import patch
from click.testing import CliRunner
from sslchecker.cli import cli
from sslchecker.lib import get_sslcert

def test_invalid_hostname():
    try:
        get_sslcert("")
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid hostname accepted")

def test_dns_failure():
    with patch("sslchecker.lib.socket.create_connection", side_effect=socket.gaierror("invalid")):
        try:
            get_sslcert("invalid.example")
        except socket.gaierror:
            pass
        else:
            raise AssertionError("DNS failure swallowed")

def test_cli_reports_tls_error():
    with patch("sslchecker.cli.get_sslcert", side_effect=ssl.SSLError("invalid cert")):
        result = CliRunner().invoke(cli, ["invalid.example"])
    assert result.exit_code != 0
    assert "TLS verification failed" in result.output
