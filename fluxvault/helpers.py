from __future__ import annotations

import socket
import asyncio
import ssl
from typing import Optional

import dns.resolver
import dns.reversename


def _get_own_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't have to be reachable
        s.connect(("10.254.254.254", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def _get_ptr(ip: str) -> str:
    canonical = dns.reversename.from_address(ip)
    resolver = dns.resolver.Resolver()
    try:
        answer = resolver.resolve(canonical, "PTR")
    except dns.resolver.NXDOMAIN:
        return ""
    else:
        return answer[0].to_text()


def _parse_ptr_to_names(ptr: str) -> list:
    # The ptr record contains the fqdn - hostname.networkname
    if not ptr or ptr == "localhost.":
        return ["", ""]

    app_name = ""
    fqdn = ptr.split(".")
    fqdn = list(filter(None, fqdn))
    host = fqdn[0]
    host = host.lstrip("flux")
    host = host.split("_")
    component_name = host[0]
    # if container name isn't specified end up with ['15f4fcb5a668', 'http']
    if len(host) > 1:
        app_name = host[1]
    return [component_name, app_name]


def get_app_and_component_name(_ip: str | None = None) -> list:
    """Gets the component and app name for a given ip. If no ip is given, gets our own details"""
    ip = _ip if _ip else _get_own_ip()
    ptr = _get_ptr(ip)
    return _parse_ptr_to_names(ptr)


async def tls_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_side: bool = False,
):
    """
    Manually perform a TLS handshake over a stream.

    Args:
        reader: The reader of the client connection.
        writer: The writer of the client connection.
        ssl_context: The SSL context to use for the TLS/SSL handshake. Defaults to None.
        server_side: Whether the connection is server-side or not.

    Note:
        If the ssl context is not passed and the connection is not server_side
        `ssl.create_default_context()` will be used.

        For Python 3.6 to 3.9 you can use ``ssl.PROTOCOL_TLS`` for the SSL context. For
        Python 3.10+ you need to either use ``ssl.PROTOCOL_TLS_CLIENT`` or
        ``ssl.PROTOCOL_TLS_SERVER`` depending on the role of the reader/writer.
    """

    if not server_side and not ssl_context:
        ssl_context = ssl.create_default_context()

    transport = writer.transport
    protocol = transport.get_protocol()

    loop = asyncio.get_event_loop()
    new_transport = await loop.start_tls(
        transport=transport,
        protocol=protocol,
        sslcontext=ssl_context,
        server_side=server_side,
    )

    reader._transport = new_transport
    writer._transport = new_transport
