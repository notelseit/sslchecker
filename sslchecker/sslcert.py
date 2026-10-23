"""X.509 certificate wrapper for modern cryptography."""
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.x509.oid import NameOID

class SSLCert:
    def __init__(self, cert):
        self.x509 = cert

    @classmethod
    def from_pem(cls, data):
        return cls(x509.load_pem_x509_certificate(data.encode() if isinstance(data, str) else data))

    @classmethod
    def from_der(cls, data):
        return cls(x509.load_der_x509_certificate(data))

    def to_pem(self):
        return self.x509.public_bytes(serialization.Encoding.PEM)

    def digest(self, name):
        algorithm = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}.get(name.lower())
        if algorithm is None:
            raise ValueError("Unsupported digest")
        return self.x509.fingerprint(algorithm())

    @property
    def cn(self):
        found = self.x509.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(found[0].value) if found else None

    @property
    def issuer(self):
        return [(a.oid.dotted_string, str(a.value)) for a in self.x509.issuer]

    @property
    def subject(self):
        return [(a.oid.dotted_string.encode(), str(a.value).encode()) for a in self.x509.subject]

    @property
    def altnames(self):
        try:
            ext = self.x509.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []

    @property
    def notbefore(self):
        return self.x509.not_valid_before_utc.replace(tzinfo=None)

    @property
    def notafter(self):
        return self.x509.not_valid_after_utc.replace(tzinfo=None)

    @property
    def has_expired(self):
        return self.x509.not_valid_after_utc <= datetime.now(timezone.utc)

    @property
    def serial(self):
        return self.x509.serial_number

    @property
    def keyinfo(self):
        key = self.x509.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return ("RSA", key.key_size)
        if isinstance(key, dsa.DSAPublicKey):
            return ("DSA", key.key_size)
        if isinstance(key, ec.EllipticCurvePublicKey):
            return ("EC", key.key_size)
        return (type(key).__name__, getattr(key, "key_size", 0))

    def __eq__(self, other):
        return isinstance(other, SSLCert) and self.digest("sha256") == other.digest("sha256")

    def __repr__(self):
        return f"<SSLCert {self.cn}>"
