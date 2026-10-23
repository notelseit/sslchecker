"""CLI for sslchecker."""
import click
from .lib import get_sslcert, render_cert

@click.command()
@click.argument("domain")
@click.option("--timeout", type=click.FloatRange(min=0.1), default=5.0, show_default=True)
def cli(domain, timeout):
    """Validate a site's TLS certificate."""
    try:
        cert = get_sslcert(domain, timeout=timeout)
    except (OSError, ValueError) as error:
        raise click.ClickException(f"TLS verification failed: {error}") from error
    render_cert(cert)
