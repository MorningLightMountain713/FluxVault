# Standard library
from __future__ import annotations

import asyncio
import binascii
import functools

import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from functools import reduce
import keyring

# 3rd party
import cryptography
import requests

from aiotinyrpc.client import RPCClient
from aiotinyrpc.auth import SignatureAuthProvider
from aiotinyrpc.exc import MethodNotFoundError
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.socket.client import EncryptedSocketClientTransport
from cryptography.x509.oid import NameOID
from ownca import CertificateAuthority
from ownca.exceptions import OwnCAInvalidCertificate
from requests.exceptions import HTTPError

# this package
from fluxvault.extensions import FluxVaultExtensions
from fluxvault.fluxkeeper_gui import FluxKeeperGui
from fluxvault.log import log

from aiotinyrpc.transports.socket.symbols import (
    AUTH_DENIED,
    PROXY_AUTH_DENIED,
    AUTH_ADDRESS_REQUIRED,
    PROXY_AUTH_ADDRESS_REQUIRED,
)

# signing_key = keyring.get_password("fluxvault_app", zelid)
# auth_provider = SignatureAuthProvider(key=signing_key)


class FluxVaultKeyError(Exception):
    pass


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
            # ToDo: change to switch in 3.10
            if agent.transport.failed_on in [AUTH_ADDRESS_REQUIRED, AUTH_DENIED]:
                signing_key = keyring.get_password(
                    "fluxvault_app", agent.transport.auth_address
                )
                if not signing_key:
                    log.error(
                        f"Signing key required in keyring for {agent.transport.auth_address}"
                    )
                    raise FluxVaultKeyError(
                        f"Signing key for address: {agent.transport.auth_address} not present in secure storage"
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


@dataclass
class FluxVaultContext:
    agents: dict
    storage: dict = field(default_factory=dict)


@dataclass
class ManagedFile:
    local_path: Path
    remote_path: Path
    local_workdir: Path
    local_crc: int = 0
    remote_crc: int = 0
    keeper_context: bool = True
    remote_file_exists: bool = False
    local_file_exists: bool = False
    in_sync: bool = False
    file_data: bytes = b""

    def validate_local_file(self):
        if self.keeper_context:
            if self.local_path.is_absolute():
                raise ValueError("All paths must be relative on Keeper")

            p = self.local_workdir / self.local_path

        try:
            with open(p, "rb") as f:
                self.file_data = f.read()
        except (FileNotFoundError, PermissionError):
            log.error(
                f"Managed file {str(self.local_workdir)}/{str(self.local_path)} not found locally or permission error... skipping!"
            )
        else:  # file opened
            self.local_file_exists = True
            self.local_crc = binascii.crc32(self.file_data)

    def compare_files(self) -> dict:
        """Flux agent (node) is requesting a file"""

        self.validate_local_file()

        if not self.remote_crc:  # remote file crc is 0 if it doesn't exist
            self.remote_file_exists = False
            if self.local_crc:
                log.info(f"Agent needs new file {self.local_path.name}... sending")

        if self.remote_crc:
            self.remote_file_exists = True
            if self.remote_crc != self.local_crc:
                self.in_sync = False
                if self.local_file_exists:
                    log.info(
                        f"Agent remote file {str(self.remote_path)} is different that local file... sending latest data"
                    )

            if self.remote_crc == self.local_crc:
                log.info(
                    f"Agent file {str(self.remote_path)} is up to date... skipping!"
                )
                self.in_sync = True


@dataclass
class ManagedFileGroup:
    files: list[ManagedFile] = field(default_factory=list)

    def remote_paths(self):
        return [str(x.remote_path) for x in self.files]

    def add(self, file: ManagedFile):
        self.files.append(file)

    def get(self, name):
        for file in self.files:
            if file.local_path.name == name:
                return file

    def to_agent_dict(self):
        return {
            str(file.remote_path): file.file_data
            for file in self.files
            if file.local_file_exists
            and (not file.remote_file_exists or not file.in_sync)
        }


@dataclass
class FluxAgentGroup:
    agents: list[RPCClient] = field(default_factory=list)

    def __iter__(self):
        yield from self.agents

    def __len__(self):
        return len(self.agents)

    def add(self, agent: RPCClient):
        self.agents.append(agent)

    def get_by_id(self, id):
        for agent in self.agents:
            if agent.id == id:
                return agent

    def get_by_socket(self, socket):
        for agent in self.agents:
            if not agent.connected:
                continue

            local = agent.transport.writer.get_extra_info("sockname")
            if local == socket:
                return agent

    def proxied_agents(self):
        # return filter(lambda x: x.is_proxied, self.agents)
        for agent in self.agents:
            if agent.is_proxied:
                yield agent

    def agent_ids(self):
        return [x.id for x in self.agents]

    def primary_agents(self):
        # return [x for x in self.agents if not x.is_proxied]
        return filter(lambda x: not x.is_proxied, self.agents)


class FluxKeeper:
    """Oracle like object than runs in your protected environment. Provides runtime
    data to your vulnerable services in a secure manner

    The end goal is to be able to secure an application's private data where visibility
    of that data is restricted to the application owner

    This class, in combination with FluxVault - is one of the first steps in fulfilling
    that goal"""

    def __init__(
        self,
        vault_dir: str,
        comms_port: int = 8888,
        app_name: str = "",
        agent_ips: list = [],
        extensions: FluxVaultExtensions = FluxVaultExtensions(),
        managed_files: list = [],
        sign_connections: bool = False,
        signing_key: str = "",
        console_server: bool = False,
    ):
        self.app_name = app_name
        self.agent_ips = agent_ips if agent_ips else self.get_agent_ips()
        self.agents = FluxAgentGroup()
        self.comms_port = comms_port
        self.extensions = extensions
        self.managed_files = ManagedFileGroup()
        self.loop = asyncio.get_event_loop()
        self.protocol = JSONRPCProtocol()
        self.vault_dir = Path(vault_dir)
        self.fluxkeeper_gui = FluxKeeperGui("127.0.0.1", 7777, self)
        self.network_state = {}
        self.fingerprints = {}

        for file_str in managed_files:
            split_file = file_str.split(":")
            local = split_file[0]
            try:
                remote = split_file[1]
            except IndexError:
                # we don't have a remote path
                remote = local
            self.managed_files.add(
                ManagedFile(Path(local), Path(remote), self.vault_dir)
            )

        self.ca = CertificateAuthority(
            ca_storage="ca", common_name="Fluxvault Keeper CA"
        )
        try:
            cert = self.ca.load_certificate("keeper.fluxvault.com")
        except OwnCAInvalidCertificate:
            cert = self.ca.issue_certificate(
                "keeper.fluxvault.com", dns_names=["keeper.fluxvault.com"]
            )

        self.cert = cert.cert_bytes
        self.key = cert.key_bytes
        self.ca_cert = self.ca.cert_bytes

        if not signing_key and sign_connections:
            raise ValueError("Signing key must be provided if signing connections")

        auth_provider = None
        if signing_key and sign_connections:
            auth_provider = SignatureAuthProvider(key=signing_key)

        if console_server:
            self.loop.run_until_complete(self.run_console())

        for ip in self.agent_ips:
            transport = EncryptedSocketClientTransport(
                ip,
                comms_port,
                auth_provider=auth_provider,
                proxy_target="",
                on_pty_data_callback=self.fluxkeeper_gui.pty_output,
                on_pty_closed_callback=self.fluxkeeper_gui.pty_closed,
            )

            flux_agent = RPCClient(self.protocol, transport)
            self.agents.add(flux_agent)
            # self.agents.update({ip: flux_agent})

        self.storage = {}  # For extensions to store data
        self.extensions.add_method(self.get_all_agents_methods)
        self.extensions.add_method(self.poll_all_agents)

    async def run_console(self):
        await self.fluxkeeper_gui.start()

    def get_agent_ips(self):
        url = f"https://api.runonflux.io/apps/location/{self.app_name}"
        res = requests.get(url, timeout=10)

        retries = 3

        for n in range(retries):
            try:
                res = requests.get(url)
                res.raise_for_status()

                break

            except HTTPError as e:
                code = e.res.status_code

                if code in [429, 500, 502, 503, 504]:
                    time.sleep(n)
                    continue

                raise

        node_ips = []
        data = res.json()
        if data.get("status") == "success":
            nodes = data.get("data")
            for node in nodes:
                ip = node["ip"].split(":")[0]
                node_ips.append(ip)

        return node_ips

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.extensions.method_map.items()}

    def get_all_agents_methods(self) -> dict:
        return self.loop.run_until_complete(self._get_agents_methods())

    @manage_transport
    async def get_agent_method(self, agent: RPCClient):
        agent_proxy = agent.get_proxy()
        methods = await agent_proxy.get_methods()

        return {agent.id: methods}

    async def _get_agents_methods(self) -> dict:
        """Queries every agent and returns a list describing what methods can be run on
        each agent"""
        tasks = []
        for agent in self.agents:
            task = asyncio.create_task(self.get_agent_method(agent))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        return reduce(lambda a, b: {**a, **b}, results)

    # gui function
    async def fingerprint_agents(self):
        for agent in self.agents:
            fingerprint = await agent.transport.fingerprint_agent()
            self.fingerprints.update({agent.id: fingerprint})
        await self.fluxkeeper_gui.fingerprints_update()

    @manage_transport
    async def get_state(self, agent: RPCClient):
        proxy = agent.get_proxy()
        self.network_state.update({agent.id: await proxy.get_state()})

    @manage_transport
    async def push_files(self, agent):
        log.debug(f"Contacting Agent {agent.id} to check if files required")

        agent_proxy = agent.get_proxy()

        files = await agent_proxy.get_all_files_crc(self.managed_files.remote_paths())
        log.debug(f"Agent {agent.id} remote file CRCs: {files}")

        if not files:
            log.warn(f"No files to sync specified... skipping!")
            return

        for file in files:
            file_name = Path(file["name"]).name
            managed_file = self.managed_files.get(file_name)
            managed_file.remote_crc = file["crc32"]

            managed_file.compare_files()

        files_to_write = self.managed_files.to_agent_dict()

        if files_to_write:
            agent_proxy.one_way = True
            # ToDo: this should return status
            await agent_proxy.write_files(files=files_to_write)

    def poll_all_agents(self):
        self.loop.run_until_complete(self.run_agent_tasks())

    async def run_agent_tasks(self, tasks: list[Callable] = []):
        if not self.agent_ips:
            log.info("No agents found... nothing to do")

        # headless mode
        # ToDo: add cli `tasks` thingee
        if not tasks and not self.fluxkeeper_gui:
            tasks = [
                self.push_files,
                self.get_state,
            ]

        tasks.insert(0, self.enroll_subordinates)

        for index, func in enumerate(tasks):
            log.info(f"Running task: {func.__name__}")
            # ToDo: if iscoroutine
            coroutines = []
            length = len(tasks)
            for agent in self.agents:
                connect = False
                disconnect = False
                if index == 0:
                    connect = True
                if index + 1 == length:
                    disconnect = True
                t = asyncio.create_task(func(agent, connect, disconnect))
                coroutines.append(t)
            try:
                await asyncio.gather(*coroutines)
            except Exception as e:
                print(repr(e))
                # pass exception to gui???

        if self.fluxkeeper_gui:
            await self.fluxkeeper_gui.network_state_update()

    @manage_transport
    async def enroll_agent(self, agent: RPCClient):
        log.info(f"Enrolling agent {agent.id}")
        proxy = agent.get_proxy()
        res = await proxy.generate_csr()
        csr_bytes = res.get("csr")

        csr = cryptography.x509.load_pem_x509_csr(csr_bytes)
        hostname = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        try:
            cert = self.ca.load_certificate(hostname)
            self.ca.revoke_certificate(hostname)
        except OwnCAInvalidCertificate:
            pass
        finally:
            # ToDo: there has to be a better way (don't delete cert)
            # start using CRL? Do all nodes need CRL - probably
            shutil.rmtree(f"ca/certs/{hostname}", ignore_errors=True)
            cert = self.ca.sign_csr(csr, csr.public_key())

        # This triggers agent to update registrar, it should probably
        # be it's own action
        await proxy.install_cert(cert.cert_bytes)
        await proxy.install_ca_cert(self.ca.cert_bytes)

        proxy.one_way = True  # ToDo: this should be a function
        await proxy.upgrade_to_ssl()
        proxy.one_way = False

        # ToDo: function (don't mutate child properties)
        agent.transport.proxy_ssl = True
        agent.transport.proxy_port += 1

    @manage_transport
    async def enroll_subordinates(self, agent: RPCClient):
        agent_proxy = agent.get_proxy()
        resp = await agent_proxy.get_subagents()

        sub_names = [k for k in resp["sub_agents"]]
        log.info(f"Agent {agent.id} has the following subordinates: {sub_names}")
        address = agent.transport.address

        for target, payload in resp.get("sub_agents").items():
            role = payload.get("role")  # not implemented yet
            enrolled = payload.get("enrolled")

            # ToDo: check if already enrolled, may have rebooted

            if not enrolled:
                flux_agent = self.create_agent(address, target)
                await self.enroll_agent(flux_agent, True, True)
                self.agents.add(flux_agent)

    def create_agent(
        self,
        address: str,
        proxy_target: str | None = None,
    ):
        transport = EncryptedSocketClientTransport(
            address,
            self.comms_port,
            auth_provider=self.auth_provider,
            proxy_target=proxy_target,
            proxy_port=self.comms_port,
            proxy_ssl=False,
            cert=self.cert,
            key=self.key,
            ca=self.ca_cert,
            on_pty_data_callback=self.fluxkeeper_gui.pty_output,
            on_pty_closed_callback=self.fluxkeeper_gui.pty_closed,
        )
        flux_agent = RPCClient(self.protocol, transport)

        return flux_agent

    def __getattr__(self, name: str) -> Callable:
        try:
            func = self.extensions.get_method(name)
        except MethodNotFoundError as e:
            raise AttributeError(f"Method does not exist: {e}")

        if func.pass_context:
            context = FluxVaultContext(self.agents)
            func = functools.partial(func, context)

        return func
