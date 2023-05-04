import functools
import io
import re
import socket
import tarfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from ownca import CertificateAuthority
from typing import Callable
import asyncio
import time
from collections import deque
import statistics
import math
import itertools
from rich.pretty import pretty_repr
from copy import copy

from rich.align import Align

import dns.resolver
import dns.reversename
import keyring
import randomname
from fluxrpc.client import RPCClient
from fluxrpc.auth import SignatureAuthProvider
from fluxrpc.transports.socket.symbols import (
    AUTH_ADDRESS_REQUIRED,
    AUTH_DENIED,
    NO_SOCKET,
    PROXY_AUTH_ADDRESS_REQUIRED,
    PROXY_AUTH_DENIED,
)
from fluxrpc.transports.socket.client import EncryptedSocketClientTransport


from fluxvault.log import log
from rich.pretty import pprint


async def handle_session(transport: EncryptedSocketClientTransport):
    if transport.session.started:
        if not transport.session.connection_attempted:
            await transport.session.start(connect=True)

            if signing_address := transport.session.signing_address:
                signing_key = await asyncio.to_thread(
                    keyring.get_password, "fluxvault_app", signing_address
                )

                if not signing_key:
                    log.error(f"Signing key required in keyring for {signing_address}")
                    # fix this no address
                    raise FluxVaultKeyError(
                        f"Reason: {transport.failed_on} Signing key not present in secure storage"
                    )

                await transport.session.connect(signing_key)


async def handle_connection(
    transport: EncryptedSocketClientTransport, connect: bool, exclusive: bool = False
) -> int | None:
    if connect:
        chan_id = await transport.connect(
            exclusive=exclusive
        )  # this gives us exclusive use of channel
        if transport.connected:
            return chan_id

    if not transport.connected:
        log.info("Transport not connected... checking connection requirements...")
        log.info(f"Failed on {transport.failed_on}")

        if transport.failed_on == NO_SOCKET:
            return

        address = ""
        # match/case
        if transport.failed_on in [AUTH_ADDRESS_REQUIRED, AUTH_DENIED]:
            address = "auth_address"
        elif transport.failed_on in [
            PROXY_AUTH_ADDRESS_REQUIRED,
            PROXY_AUTH_DENIED,
        ]:
            address = "proxy_auth_address"

        signing_key = keyring.get_password("fluxvault_app", getattr(transport, address))

        if not signing_key:
            log.error(
                f"Signing key required in keyring for {getattr(transport, address)}"
            )
            raise FluxVaultKeyError(
                f"Reason: {transport.failed_on} Signing key for address: {getattr(transport, address)} not present in secure storage"
            )

        auth_provider = SignatureAuthProvider(key=signing_key)
        transport.auth_provider = auth_provider

        return await transport.connect(exclusive=exclusive)


def manage_transport(f=None, exclusive: bool = False):
    def inner(f):
        @functools.wraps(f)
        async def wrapper(*args, **kwargs):
            # Surely there is a better way
            agent = None
            for arg in args:
                if isinstance(arg, RPCClient):
                    agent = arg
                    break

            transport: EncryptedSocketClientTransport = agent.transport

            disconnect = kwargs.pop("disconnect", True)
            connect = kwargs.pop("connect", True)
            in_session = kwargs.pop("in_session", False)

            log.debug(
                f"In wrapper for {f.__name__}, connect: {connect}, disconnect: {disconnect}, in_session: {in_session} agent: {agent.id}"
            )

            if in_session:
                # this doesn't actually return a chan_id (it should)
                chan_id = await handle_session(transport)
            else:
                chan_id = await handle_connection(transport, connect, exclusive)

            if not transport.connected:
                log.error(f"{agent.id}: Connection failed... returning")
                return

            res = await f(*args, **kwargs)

            if not in_session and disconnect:
                await transport.disconnect(chan_id)

            return res

        return wrapper

    if f:
        return inner(f)
    else:
        return inner


class SyncStrategy(Enum):
    STRICT = 1
    ALLOW_ADDS = 2
    ENSURE_CREATED = 3


class AppMode(Enum):
    FILESERVER = 1
    SINGLE_COMPONENT = 2
    MULTI_COMPONENT = 3
    UNKNOWN = 4


class ContainerState(Enum):
    DEFAULT = "DEFAULT"
    ERROR = "ERROR"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    UNCONTACTABLE = "UNCONTACTABLE"


def bytes_to_human(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def human_to_bytes(size: str):
    units = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12}

    number, unit = list(filter(None, re.split(r"(\d+)", size)))
    return int(float(number) * units[unit])


def tar_object(dir_or_file: Path) -> bytes:
    log.info(f"About to tar {dir_or_file}")
    fh = io.BytesIO()
    # lol, hope the files aren't too big, or, you got plenty of ram
    with tarfile.open(fileobj=fh, mode="w|bz2") as tar:
        tar.add(
            dir_or_file,
            arcname="",
        )
    log.info("Tarring complete")
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


class AgentId(tuple):
    ...


class UnixTime(float):
    ...


# class SymbolDeque(deque):
#     def __init__(self, symbols: list = ["\U0001F7E9", "\U0001F7E5"]):
#         self.update_symbols(symbols)

#     def update_symbols(self, symbols: list):
#         # meh, IndexOutOfRange
#         self.positive = symbols[0]
#         self.negative = symbols[1]

#     def append(self, item):
#         if item:
#             super(SymbolDeque, self).append(self.positive)
#         else:
#             super(SymbolDeque, self).append(self.negative)


@dataclass
class HitCounter:
    raw: deque[bool] = field(default_factory=lambda: deque([], maxlen=60))
    one_minute: deque[bool] = field(default_factory=lambda: deque([], maxlen=15))
    fifteen_minute: deque[bool] = field(default_factory=lambda: deque([], maxlen=15))
    one_hour: deque[bool] = field(default_factory=lambda: deque([], maxlen=15))
    last_update: UnixTime = 0
    counter: int = 0

    @staticmethod
    def advance_queue(subject: deque, previous: deque | list) -> bool:
        initial_state = copy(subject)

        if all(x is None for x in previous):
            data = None
        else:
            data = all(previous)

        subject.append(data)

        return initial_state != subject

    def update(self, hit: bool | None):
        changed = False
        self.counter += 1
        raw_copy = copy(self.raw)
        self.raw.append(hit)

        if raw_copy != self.raw:
            changed = True

        if self.counter % (60 * 1) == 0:
            changed = self.advance_queue(self.one_minute, self.raw)

        if self.counter % (60 * 15) == 0:
            changed = self.advance_queue(self.fifteen_minute, self.one_minute)

        if self.counter % (60 * 60) == 0:
            changed = self.advance_queue(self.one_hour, list(self.fifteen_minute)[-4:])

            self.counter = 0

        if changed:
            self.last_update = time.monotonic()


@dataclass
class RTT(tuple):
    raw: deque[float] = field(default_factory=lambda: deque([], maxlen=60))
    one_minute: deque[float] = field(default_factory=lambda: deque([], maxlen=15))
    fifteen_minute: deque[float] = field(default_factory=lambda: deque([], maxlen=4))
    one_hour: deque[float] = field(default_factory=lambda: deque([], maxlen=24))
    low: float = 0
    high: float = 0
    average: float = 0

    def __repr__(self):
        me = self.__dict__.copy()
        del me["raw"]
        return pretty_repr(me)


@dataclass
class StateTransition:
    offline_to_online: bool
    time: UnixTime = field(default_factory=time.time)


@dataclass
class NodeContactState:
    first_contact: UnixTime = field(default_factory=time.time)
    transitions: list[StateTransition] = field(default_factory=list)
    in_quarantine: bool = False
    quarantine_timer: UnixTime = 0
    total_count: int = 0
    total_missed_count: int = 0
    rtt: RTT = field(default_factory=RTT)
    hit_counter: HitCounter = field(default_factory=HitCounter)
    misses: deque[float] = field(default_factory=lambda: deque([], maxlen=60))

    @property
    def active(self) -> bool:
        if self.transitions:
            return self.transitions[-1].offline_to_online
        else:
            return True

    @property
    def transition_count(self) -> int:
        return len(self.transitions)

    @property
    def latest_transition(self) -> StateTransition | None:
        if self.transitions:
            return self.transitions[-1]

    @property
    def last_state_change_time(self) -> UnixTime:
        return 0 if not self.transitions else self.latest_transition.time

    @property
    def one_minute_miss_count(self) -> int:
        count = 0
        one_minute_ago = time.time() - 60

        for miss in reversed(self.misses):
            if miss > one_minute_ago:
                count += 1
            else:
                break

        return count

    def increment_counters(self):
        self.total_missed_count += 1
        self.misses.append(time.time())

    def quarantine(self):
        self.in_quarantine = True
        self.quarantine_timer = time.perf_counter()

    def dequarantine(self):
        self.in_quarantine = False
        self.quarantine_timer = 0

    def update_hit_counter(self, hit: bool | None):
        self.hit_counter.update(hit)

    def update_rtt(self, rtt: float):
        rtt = round(rtt, 3)
        self.rtt.raw.append(rtt)

        if self.total_count == 0:
            return

        if self.total_count % (60 * 1) == 0:
            one_min_average = statistics.mean(self.rtt.raw)
            self.rtt.one_minute.append(round(one_min_average, 3))

        if self.total_count % (60 * 15) == 0:
            fifteen_min_average = statistics.mean(self.rtt.one_minute)
            self.rtt.fifteen_minute.append(round(fifteen_min_average, 3))

        if self.total_count % (60 * 60) == 0:
            one_hour_average = statistics.mean(self.rtt.fifteen_minute)
            self.rtt.one_hour.append(round(one_hour_average, 3))

        rtt_count = self.total_count - self.total_missed_count

        # average block
        if self.rtt.average == 0:
            self.rtt.average = rtt
        else:
            rtt_total = rtt_count * self.rtt.average
            rtt_total + rtt
            self.rtt_average = round(rtt_total / rtt, 3)

        # high / low block
        if self.rtt.low == 0 or rtt < self.rtt.low:
            self.rtt.low = rtt

        elif rtt > self.rtt.high:
            self.rtt.high = rtt


@dataclass
class FluxTask:
    name: str
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    func: Callable | None = None


@dataclass
class FluxVaultContext:
    agents: dict
    ca: CertificateAuthority
    storage: dict = field(default_factory=dict)


@dataclass
class RemoteStateDirective:
    """"""

    name: str | None = None
    content_source: Path | None = None
    remote_dir: Path | None = None
    sync_strategy: SyncStrategy = SyncStrategy.ENSURE_CREATED

    # @property
    # def absolute_dir(self):
    #     if not any([self.workdir, self.prefix]):
    #         ...
    #     # maybe do some sanity stuff here, make sure at least one of them are absolute
    #     match self.prefix:
    #         case x if x and x.is_absolute():
    #             return x
    #         case x if x:
    #             return self.workdir / self.prefix
    #         case x if not x:
    #             return self.workdir

    @property
    def local_absolute_path(self):
        return None if not self.content_source else self.content_source / self.name

    def serialize(self):
        return {
            "content_source": str(self.content_source),
            "prefix": str(self.remote_dir),
            "sync_strategy": self.sync_strategy.name,
        }


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

    return comp, app
