"""Retrieve TLS certificates with verified hostname and trust chain."""
from datetime import datetime, timezone
from urllib.parse import urlparse
import socket
import ssl
import click
from .sslcert import SSLCert

def get_sslcert(domain, timeout=5.0):
    parsed = urlparse(domain if "://" in domain else "//" + domain)
    host = parsed.hostname
    if not host:
        raise ValueError("Valid hostname required")
    context = ssl.create_default_context()
    with socket.create_connection((host, parsed.port or 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            data = connection.getpeercert(binary_form=True)
    if not data:
        raise ssl.SSLError("No peer certificate")
    return SSLCert.from_der(data)

def _expire_in(cert):
    return (cert.x509.not_valid_after_utc - datetime.now(timezone.utc)).days

def _warning(cert):
    return 0 <= _expire_in(cert) < 30

def _secured(cert):
    return not cert.has_expired

def render_cert(cert):
    remaining = _expire_in(cert)
    color = "red" if cert.has_expired else "yellow" if _warning(cert) else "green"
    click.secho("# SSL secured #" if not cert.has_expired else "# SSL unsecured #", fg=color, bold=True)
    click.echo(f"Common name: {cert.cn}")
    click.echo(f"Valid from: {cert.notbefore} UTC")
    click.echo(f"Expiration date: {cert.notafter} UTC")
    click.echo(f"Expires in: {remaining} days")
    click.echo(f"Key: {cert.keyinfo[0]} ({cert.keyinfo[1]} bits)")
    click.echo("Issued by:")
    for key, value in cert.issuer:
        click.echo(f"  {key}: {value}")
