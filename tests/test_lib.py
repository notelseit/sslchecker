"""Offline TLS network and hostname regression tests."""
from unittest.mock import patch
import socket
import pytest
from sslchecker.lib import get_sslcert


def test_invalid_hostname():
    with pytest.raises(ValueError):
        get_sslcert("")


def test_url_with_path_uses_correct_hostname():
    with patch("sslchecker.lib.socket.create_connection", side_effect=socket.gaierror("offline")) as mocked:
        with pytest.raises(socket.gaierror):
            get_sslcert("https://example.com/path")
    assert mocked.call_args.args[0] == ("example.com", 443)


def test_nondefault_port():
    with patch("sslchecker.lib.socket.create_connection", side_effect=socket.gaierror("offline")) as mocked:
        with pytest.raises(socket.gaierror):
            get_sslcert("example.com:8443")
    assert mocked.call_args.args[0] == ("example.com", 8443)
