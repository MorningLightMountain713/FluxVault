import functools
import io
import re
import socket
import tarfile
from enum import Enum
from pathlib import Path

import dns.resolver
import dns.reversename
import keyring
import randomname
from fluxrpc.auth import SignatureAuthProvider
from fluxrpc.transports.socket.symbols import (
    AUTH_ADDRESS_REQUIRED,
    AUTH_DENIED,
    NO_SOCKET,
    PROXY_AUTH_ADDRESS_REQUIRED,
    PROXY_AUTH_DENIED,
)

from fluxvault.log import log


def manage_transport(f):
    @functools.wraps(f)
    async def wrapper(*args, **kwargs):
        # ToDO: brittle. Popping args feels hella dirty
        func_args = list(args)
        disconnect = func_args.pop()
        connect = func_args.pop()
        agent = func_args[-1]

        if connect:
            await agent.transport.connect()

        if not agent.transport.connected:
            log.info("Transport not connected... checking connection requirements...")
            log.info(f"Failed on {agent.transport.failed_on}")

            if agent.transport.failed_on == NO_SOCKET:
                return

            address = ""
            if agent.transport.failed_on in [AUTH_ADDRESS_REQUIRED, AUTH_DENIED]:
                address = "auth_address"
            elif agent.transport.failed_on in [
                PROXY_AUTH_ADDRESS_REQUIRED,
                PROXY_AUTH_DENIED,
            ]:
                address = "proxy_auth_address"

            signing_key = keyring.get_password(
                "fluxvault_app", getattr(agent.transport, address)
            )

            if not signing_key:
                log.error(
                    f"Signing key required in keyring for {getattr(agent.transport, address)}"
                )
                raise FluxVaultKeyError(
                    f"Reason: {agent.transport.failed_on} Signing key for address: {getattr(agent.transport, address)} not present in secure storage"
                )

            auth_provider = SignatureAuthProvider(key=signing_key)
            agent.transport.auth_provider = auth_provider
            await agent.transport.connect()

            if not agent.transport.connected:
                log.error("Cannot connect after retrying with authentication...")
                return

        res = await f(*func_args, **kwargs)

        if disconnect:
            await agent.transport.disconnect()

        return res

    return wrapper


class SyncStrategy(Enum):
    STRICT = 1
    ALLOW_ADDS = 2
    ENSURE_CREATED = 3


def bytes_to_human(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def human_to_bytes(size: str):
    # macOS etc
    units = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12}

    # Alternative unit definitions, notably used by Windows:
    # units = {"B": 1, "KB": 2**10, "MB": 2**20, "GB": 2**30, "TB": 2**40}

    number, unit = list(filter(None, re.split("(\d+)", size)))
    return int(float(number) * units[unit])


def tar_object(dir_or_file: Path) -> bytes:
    fh = io.BytesIO()
    # lol, hope the files aren't too big, or, you got plenty of ram
    with tarfile.open(fileobj=fh, mode="w|bz2") as tar:
        tar.add(
            dir_or_file,
            arcname="",
        )
    return fh.getvalue()


def size_of_object(path: Path) -> int:
    obj_type = "File"
    # ToDo: this breaks if path doesn't exist
    if path.is_dir():
        obj_type = "Directory"

        size = sum(f.stat().st_size for f in path.glob("**/*") if f.is_file())

    elif path.is_file():
        size = path.stat().st_size

    # this feels wrong here
    log.info(f"Syncing {obj_type} {path} of size { bytes_to_human(size)}")

    return size


class FluxVaultKeyError(Exception):
    pass


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
    comp, app = _parse_ptr_to_names(ptr)

    if not comp or not app:
        comp = randomname.get_name()
        app = "testapp"

    return (comp, app)
