"""Tests for the local certificate authority.

The point of all this is one measured fact: BambuStudio answers a fatal
``unknown_ca`` alert to a self-signed certificate. Only a chain the user has
chosen to trust gets past it.
"""

import socket
import ssl
import threading

import pytest
from cryptography import x509

from pandaproxy.ca import (
    CA_CERT_FILENAME,
    CA_KEY_FILENAME,
    create_ca,
    is_signed_by,
    issue_leaf,
    load_ca,
)


@pytest.fixture
def paths(tmp_path):
    return (
        tmp_path / CA_CERT_FILENAME,
        tmp_path / CA_KEY_FILENAME,
        tmp_path / "pandaproxy.crt",
        tmp_path / "pandaproxy.key",
    )


class TestAuthority:
    """Creating and reloading the authority."""

    def test_nothing_to_load_at_first(self, paths):
        ca_cert, ca_key, _, _ = paths
        assert load_ca(ca_cert, ca_key) is None

    def test_created_authority_reloads_identically(self, paths):
        ca_cert, ca_key, _, _ = paths
        created, _ = create_ca(ca_cert, ca_key)
        reloaded = load_ca(ca_cert, ca_key)
        assert reloaded is not None
        assert reloaded[0].serial_number == created.serial_number

    def test_it_is_actually_a_ca(self, paths):
        ca_cert, ca_key, _, _ = paths
        cert, _ = create_ca(ca_cert, ca_key)
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert basic.ca is True
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert usage.key_cert_sign is True

    def test_private_key_is_not_world_readable(self, paths):
        # It is the one file here that must never reach a slicer.
        ca_cert, ca_key, _, _ = paths
        create_ca(ca_cert, ca_key)
        assert ca_key.stat().st_mode & 0o077 == 0

    def test_unreadable_authority_is_reported_as_absent(self, paths):
        ca_cert, ca_key, _, _ = paths
        ca_cert.write_text("not a certificate")
        ca_key.write_text("not a key")
        assert load_ca(ca_cert, ca_key) is None


class TestLeaf:
    """The certificate the proxy actually presents."""

    def test_signed_by_the_authority(self, paths):
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(cert, key, leaf, leaf_key, san_ips=["10.0.0.66"])
        assert is_signed_by(leaf, cert)

    def test_a_foreign_certificate_is_not(self, paths):
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(cert, key, leaf, leaf_key)
        other, _ = create_ca(
            ca_cert_p.with_suffix(".other"), ca_key_p.with_suffix(".other")
        )
        assert not is_signed_by(leaf, other)

    def test_the_chain_is_served_not_just_the_leaf(self, paths):
        # A client that trusts only the authority still needs the path to it.
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(cert, key, leaf, leaf_key)
        assert leaf.read_text().count("BEGIN CERTIFICATE") == 2

    def test_addresses_reach_the_sans(self, paths):
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(
            cert,
            key,
            leaf,
            leaf_key,
            san_ips=["127.0.0.1", "10.0.0.66"],
            san_dns=["localhost"],
        )
        parsed = x509.load_pem_x509_certificate(leaf.read_bytes())
        san = parsed.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        assert {str(i) for i in san.get_values_for_type(x509.IPAddress)} == {
            "127.0.0.1",
            "10.0.0.66",
        }
        assert "localhost" in san.get_values_for_type(x509.DNSName)

    def test_a_bad_address_is_skipped_not_fatal(self, paths):
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(cert, key, leaf, leaf_key, san_ips=["10.0.0.66", "not-an-ip"])
        parsed = x509.load_pem_x509_certificate(leaf.read_bytes())
        san = parsed.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        assert {str(i) for i in san.get_values_for_type(x509.IPAddress)} == {
            "10.0.0.66"
        }

    def test_leaf_cannot_sign_further_certificates(self, paths):
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(cert, key, leaf, leaf_key)
        parsed = x509.load_pem_x509_certificate(leaf.read_bytes())
        basic = parsed.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert basic.ca is False


class TestStrictClientAccepts:
    """The whole point: a verifying client must be satisfied."""

    def test_client_trusting_only_the_ca_completes_the_handshake(self, paths):
        # Mirrors what BambuStudio does - verify the chain, check the name
        # against the address it dialled - which a self-signed certificate
        # answers with a fatal unknown_ca alert.
        ca_cert_p, ca_key_p, leaf, leaf_key = paths
        cert, key = create_ca(ca_cert_p, ca_key_p)
        issue_leaf(cert, key, leaf, leaf_key, san_ips=["127.0.0.1"])

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(leaf, leaf_key)

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        failure: list[BaseException] = []

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except BaseException as e:
                failure.append(e)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(ca_cert_p)
            client_ctx.check_hostname = True
            with (
                socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
                client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
            ):
                assert tls.getpeercert() is not None
        finally:
            listener.close()
            thread.join(timeout=5)

    def test_a_self_signed_certificate_is_refused(self, paths, tmp_path):
        # Guards the reason this module exists: proves the strict client used
        # above really would reject what the proxy used to present.
        from pandaproxy.helper import generate_self_signed_cert

        ca_cert_p, ca_key_p, _, _ = paths
        create_ca(ca_cert_p, ca_key_p)
        selfsigned = tmp_path / "self.crt"
        selfsigned_key = tmp_path / "self.key"
        generate_self_signed_cert(
            common_name="PandaProxy",
            san_ips=["127.0.0.1"],
            output_cert=selfsigned,
            output_key=selfsigned_key,
        )

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(selfsigned, selfsigned_key)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                with server_ctx.wrap_socket(conn, server_side=True):
                    pass
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(ca_cert_p)
            client_ctx.check_hostname = True
            with (
                socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
                pytest.raises(ssl.SSLCertVerificationError),
            ):
                client_ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        finally:
            listener.close()
            thread.join(timeout=5)
