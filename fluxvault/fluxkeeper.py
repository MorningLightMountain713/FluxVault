# Standard library

# So you don't have to forward reference in typing own class. See FsEntry
from __future__ import annotations
import asyncio
import functools
import shutil
from dataclasses import dataclass, field
from functools import reduce
from pathlib import Path
from typing import Callable
import aiofiles
from enum import Enum
import time


# 3rd party
import aiohttp
import cryptography
from fluxrpc.auth import SignatureAuthProvider
from fluxrpc.client import RPCClient, RPCProxy
from fluxrpc.exc import MethodNotFoundError
from fluxrpc.protocols.jsonrpc import JSONRPCProtocol
from fluxrpc.transports.socket.client import EncryptedSocketClientTransport
from cryptography.x509.oid import NameOID
from ownca import CertificateAuthority
from ownca.exceptions import OwnCAInvalidCertificate

# this package
from fluxvault.app_init import setup_filesystem_and_wallet
from fluxvault.extensions import FluxVaultExtensions
from fluxvault.fluxapp_config import FileSystemeGroup, FileSystemEntry, FluxAppConfig
from fluxvault.fluxkeeper_gui import FluxKeeperGui
from fluxvault.helpers import (
    FluxVaultKeyError,
    SyncStrategy,
    bytes_to_human,
    manage_transport,
    size_of_object,
    tar_object,
)
from fluxvault.log import log


@dataclass
class SyncRequest:
    path: str
    data: bytes
    is_dir: bool
    uncompressed: bool

    def serialize(self):
        return self.__dict__


class FsType(Enum):
    DIRECTORY = 1
    FILE = 2
    UNKNOWN = 3


@dataclass
class FsEntry:
    fs_type: FsType
    path: Path
    size: int
    children: list[FsEntry] = field(default_factory=list)

    def __str__(self):
        decendants = [str(x) for x in self.children]
        decendants_str = "\n\t".join(decendants)
        return f"<FsEntry type: {self.fs_type}, size: {self.size} path: {self.path}\n\t{decendants_str}"


@dataclass
class FluxVaultContext:
    agents: dict
    storage: dict = field(default_factory=dict)


class FluxKeeper:
    """Runs in your protected environment. Provides runtime
    data to your vulnerable services in a secure manner

    The end goal is to be able to secure an application's private data where visibility
    of that data is restricted to the application owner
    """

    # GUI hidden via cli, no where near ready, should probably disable
    def __init__(
        self,
        apps_config: list[FluxAppConfig],
        vault_dir: Path,
        gui: bool = False,
    ):
        self.apps_config = apps_config
        # ToDo: configurable port
        self.gui = FluxKeeperGui("127.0.0.1", 7777, self)

        self.loop = asyncio.get_event_loop()
        self.managed_apps: list[FluxAppManager] = []
        self.vault_dir = vault_dir
        self.root_dir = setup_filesystem_and_wallet(self.vault_dir)

        log.info(f"App Data directory: {self.root_dir}")
        log.info(f"Vault directory: {self.vault_dir}")

        self.init_certificate_authority()
        self.configure_apps()

        if gui:
            self.start_gui()

    def init_certificate_authority(self):
        common_name = "keeper.fluxvault.com"

        self.ca = CertificateAuthority(
            ca_storage=f"{str(self.root_dir / 'ca')}", common_name="Fluxvault Keeper CA"
        )

        try:
            cert = self.ca.load_certificate(common_name)
        except OwnCAInvalidCertificate:
            cert = self.ca.issue_certificate(common_name, dns_names=[common_name])

        self.cert = cert.cert_bytes
        self.key = cert.key_bytes
        self.ca_cert = self.ca.cert_bytes

    def configure_apps(self):
        for app_config in self.apps_config:
            app_config.update_paths(self.vault_dir / app_config.name)
            app_config.build_catalogue()
            app_config.validate_local_objects()
            flux_app = FluxAppManager(self, app_config)
            self.managed_apps.append(flux_app)

    def start_gui(self):
        self.loop.run_until_complete(self.gui.start())

    async def manage_apps(self):
        for app in self.managed_apps:
            while True:
                await app.run_agent_tasks()
                if app.app_config.run_once:
                    break
                log.info(
                    f"sleeping {app.app_config.polling_interval} seconds for app {app.app_config.name}..."
                )
                await asyncio.sleep(app.app_config.polling_interval)


class FluxAppManager:
    def __init__(
        self,
        keeper: FluxKeeper,
        config: FluxAppConfig,
        extensions: FluxVaultExtensions = FluxVaultExtensions(),
    ):
        self.keeper = keeper
        self.app_config = config
        self.agents = []
        self.extensions = extensions
        self.network_state = {}

        self.build_agents()
        self.register_extensions()

    def __iter__(self):
        yield from self.agents

    def __len__(self):
        return len(self.agents)

    @staticmethod
    async def get_agent_ips(app_name: str) -> list:
        url = f"https://api.runonflux.io/apps/location/{app_name}"
        timeout = aiohttp.ClientTimeout(connect=10)
        retries = 3

        # look at making session appwide
        async with aiohttp.ClientSession() as session:
            for n in range(retries):
                try:
                    async with session.get(url, timeout=timeout) as resp:
                        if resp.status in [429, 500, 502, 503, 504]:
                            log.error(f"bad response {resp.status}... retrying")
                            continue

                        data = await resp.json()
                        break

                except aiohttp.ClientConnectorError:
                    log.error(f"Unable to connect to {url}... retrying")
                    await asyncio.sleep(n)
                    continue

        node_ips = []
        if data.get("status") == "success":
            nodes = data.get("data")
            for node in nodes:
                ip = node["ip"].split(":")[0]
                node_ips.append(ip)
        else:
            log.error("Return status from Flux api was not successful for agent IPs")

        return node_ips

    def add(self, agent: RPCClient):
        self.agents.append(agent)

    def get_by_id(self, id):
        for agent in self.agents:
            if agent.id == id:
                return agent

    def get_by_socket(self, socket: tuple):
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

    def agent_ids(self) -> list:
        return [x.id for x in self.agents]

    def primary_agents(self) -> filter:
        # return [x for x in self.agents if not x.is_proxied]
        return list(filter(lambda x: not x.is_proxied, self.agents))

    def build_agents(self):
        agent_ips = (
            self.app_config.agent_ips
            if self.app_config.agent_ips
            else self.get_agent_ips(self.app_config.name)
        )

        if not self.app_config.signing_key and self.app_config.sign_connections:
            raise ValueError("Signing key must be provided if signing connections")

        auth_provider = None
        if self.app_config.sign_connections and self.app_config.signing_key:
            auth_provider = SignatureAuthProvider(key=self.app_config.signing_key)

        for ip in agent_ips:
            transport = EncryptedSocketClientTransport(
                ip,
                self.app_config.comms_port,
                auth_provider=auth_provider,
                proxy_target="",
                on_pty_data_callback=self.keeper.gui.pty_output,
                on_pty_closed_callback=self.keeper.gui.pty_closed,
            )
            flux_agent = RPCClient(
                JSONRPCProtocol(), transport, (self.app_config.name, ip, "fluxagent")
            )
            self.add(flux_agent)

    def register_extensions(self):
        self.extensions.add_method(self.get_all_agents_methods)
        self.extensions.add_method(self.poll_all_agents)

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.extensions.method_map.items()}

    def get_all_agents_methods(self) -> dict:
        return self.keeper.loop.run_until_complete(self._get_agents_methods())

    @manage_transport
    async def get_agent_methods(self, agent: RPCClient):
        agent_proxy = agent.get_proxy()
        methods = await agent_proxy.get_methods()

        return {agent.id: methods}

    async def _get_agents_methods(self) -> dict:
        """Queries every agent and returns a list describing what methods can be run on
        each agent"""
        tasks = []
        for agent in self.agents:
            task = asyncio.create_task(self.get_agent_methods(agent))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        return reduce(lambda a, b: {**a, **b}, results)

    @manage_transport
    async def get_state(self, agent: RPCClient):
        proxy = agent.get_proxy()
        self.network_state.update({agent.id: await proxy.get_state()})

    @staticmethod
    def get_extra_objects(
        managed_object: FileSystemEntry,
        local_hashes: dict[str, int],
        remote_hashes: dict[str, int],
    ) -> tuple[list[Path], int]:
        count = 0
        extras = []

        for remote_name in remote_hashes:
            remote_name = Path(remote_name)

            relative_path = str(remote_name.relative_to(managed_object.remote_prefix))

            # this won't happen anymore. Remote prefix will always be absolute
            # for a directory (only get this via chroot config)
            # if managed_object.is_remote_prefix_absolute():
            #     relative_path = str(
            #         remote_name.relative_to(managed_object.remote_prefix)
            #     )
            # else:
            #     relative_path = str(
            #         remote_name.relative_to(managed_object.remote_workdir)
            #     )

            local_name = local_hashes.get(relative_path, None)

            if local_name is None:
                count += 1
                if not extras:
                    extras.append(remote_name)

                extras = FileSystemeGroup.filter_hierarchy(remote_name, extras)

        return (extras, count)

    @staticmethod
    def get_missing_or_modified_objects(
        managed_object: FileSystemEntry,
        local_hashes: dict[str, int],
        remote_hashes: dict[str, int],
    ) -> tuple[list[Path], int, int]:
        # can't use zip here as we don't know remote lengths
        # set would work for filenames but not hashes
        # iterate hashes and find missing / modified objects

        missing = 0
        modified = 0
        candidates: list[Path] = []

        for local_path, local_crc in local_hashes.items():
            remote_absolute = managed_object.absolute_remote_dir / local_path
            # these local hashes have been formatted in "common" format
            local_path = Path(local_path)

            # this should always be found, we asked for the hash.
            remote_crc = remote_hashes.get(str(remote_absolute), None)
            if remote_crc is None:  # 0 means empty file. Should just hash the filename
                missing += 1

            elif remote_crc != local_crc:
                modified += 1

            if remote_crc is None or remote_crc != local_crc:
                candidates.append(local_path)

        return (candidates, missing, modified)

    def resolve_object_deltas(
        self,
        managed_object: FileSystemEntry,
        local_hashes: dict[str, int],
        remote_hashes: dict[str, int],
    ) -> tuple[list[Path], list[Path]]:
        candidates, missing, modified = self.get_missing_or_modified_objects(
            managed_object, local_hashes, remote_hashes
        )

        extra_objects, unknown = self.get_extra_objects(
            managed_object, local_hashes, remote_hashes
        )

        log.info(
            f"{missing} missing object(s), {modified} modified object(s) and {unknown} extra object(s)... fixing"
        )
        return (candidates, extra_objects)

    # async def stream_file(self, local_path, remote_path, agent_proxy: RPCProxy):
    #     eof = False
    #     start = time.time()
    #     async with aiofiles.open(local_path, "rb") as f:
    #         while True:
    #             if eof:
    #                 break

    #             # 50Mb
    #             MAX_READ = 1048576 * 50
    #             # data = await f.read(MAX_READ)
    #             # print(f"acutal read data:{bytes_to_human(len(data))}")

    #             # if not data or len(data) < MAX_READ:
    #             #     eof = True
    #             # log.debug(f"writing {bytes_to_human(len(data))} for file {remote_path}")
    #             agent_proxy.notify()
    #             eof = await agent_proxy.write_object(
    #                 str(remote_path), False, await f.read(MAX_READ), MAX_READ
    #             )
    #     end = time.time()
    #     log.info(f"File transfer took: {end - start} seconds")

    async def write_objects(
        self,
        agent_proxy: RPCProxy,
        managed_object: FileSystemEntry,
        objects_to_add: list[Path],
    ) -> dict:
        MAX_INBAND_FILESIZE = 1048576 * 50
        inband = False
        to_stream = []

        # the objects to add - we don't know if they're dirs or files

        size = sum(
            (managed_object.local_workdir / f).stat().st_size
            for f in objects_to_add
            if (managed_object.local_workdir / f).is_file()
        )
        log.info(f"Sending {bytes_to_human(size)} across {len(objects_to_add)} files")

        if size < MAX_INBAND_FILESIZE:
            inband = True

        for fs_entry in objects_to_add:
            abs_local_path = managed_object.local_workdir / fs_entry

            abs_remote_path = str(managed_object.absolute_remote_dir / fs_entry)

            if abs_local_path.is_dir():
                # Only need to do for empty dirs but currently doing on all dirs (wasteful as they will get created anyways)
                await agent_proxy.write_object(abs_remote_path, True, b"")
            elif abs_local_path.is_file():
                # read whole file in one go as it's less than 50Mb
                if inband:
                    async with aiofiles.open(abs_local_path, "rb") as f:
                        await agent_proxy.write_object(
                            abs_remote_path, False, await f.read()
                        )
                    continue
                else:
                    to_stream.append((abs_local_path, abs_remote_path))
        if to_stream:
            transport = agent_proxy.get_transport()
            await transport.stream_files(to_stream)

    async def resolve_file_state(
        self, managed_object: FileSystemEntry, agent_proxy: RPCProxy
    ):
        abs_local_path = managed_object.absolute_local_path

        size = size_of_object(abs_local_path)
        log.info(
            f"File {managed_object.local_path} with size {bytes_to_human(size)} is about to be transferred"
        )
        # this seems a bit strange but writing directory uses the same interface
        # and they don't know who the file names are, the just have the associated
        # managed_object
        await self.write_objects(
            agent_proxy, managed_object, [managed_object.local_path]
        )

        managed_object.in_sync = True
        managed_object.remote_object_exists = True

    async def resolve_directory_state(
        self, managed_object: FileSystemEntry, agent_proxy: RPCProxy
    ) -> dict:
        remote_path = str(managed_object.absolute_remote_path)

        # this is different from the global get_all_object_hashes - this adds
        # all the hashes together, get_directory_hashes keeps them seperate
        remote_hashes = await agent_proxy.get_directory_hashes(remote_path)
        local_hashes = managed_object.get_directory_hashes()
        # these are in remote absolute form
        objects_to_add, objects_to_remove = self.resolve_object_deltas(
            managed_object, local_hashes, remote_hashes
        )

        if managed_object.sync_strategy == SyncStrategy.STRICT and objects_to_remove:
            # we need to remove extra objects
            # ToDo: sort serialization so you can pass in paths etc
            to_delete = [str(x) for x in objects_to_remove]
            await agent_proxy.remove_objects(to_delete)
            log.info(
                f"Sync strategy set to {SyncStrategy.STRICT.name}, deleting extra objects: {to_delete}"
            )
        elif SyncStrategy.ALLOW_ADDS:
            managed_object.validated_remote_crc = managed_object.remote_crc

        log.info(
            f"Deltas resolved... {len(objects_to_add)} object(s) need to be resynced: {objects_to_add}"
        )

        await self.write_objects(agent_proxy, managed_object, objects_to_add)

        managed_object.in_sync = True
        managed_object.remote_object_exists = True

    @manage_transport
    async def sync_objects(self, agent: RPCClient):
        log.debug(f"Contacting Agent {agent.id} to check if files required")
        # ToDo: fix formatting nightmare between local / common / remote
        component_config = self.app_config.get_component(agent.id[2])

        # BUILD DIRECTORIES FIRST!!!!

        if not component_config:
            # each component must be specified
            log.warn(
                f"No config found for component {agent.id[2]}, this component will only get globally specified files"
            )
            return

        remote_paths = component_config.file_manager.absolute_remote_paths()
        remote_dirs = component_config.file_manager.absolute_remote_dirs()

        agent_proxy = agent.get_proxy()

        # if not component_config.directories_built:
        #     dirs = [{"path": x, "is_dir": False, "data": b""} for x in remote_dirs]
        #     await agent_proxy.write_objects(dirs)
        #     component_config.directories_built = True

        remote_fs_objects = await agent_proxy.get_all_object_hashes(remote_paths)
        log.debug(f"Agent {agent.id} remote file CRCs: {remote_fs_objects}")

        if not remote_fs_objects:
            log.warn(f"No objects to sync for {agent.id} specified... skipping!")
            return

        for remote_fs_object in remote_fs_objects:
            remote_path = Path(remote_fs_object["name"])
            managed_object = component_config.file_manager.get_object_by_remote_path(
                remote_path
            )

            if not managed_object:
                log.warn(f"managed object: {remote_path} not found in component config")
                return

            managed_object.remote_crc = remote_fs_object["crc32"]
            managed_object.compare_objects()

            if not managed_object.local_object_exists:
                log.warn(
                    f"Remote object exists but local doesn't: {managed_object.local_path}. Local workdir: {managed_object.local_workdir}"
                )
                continue

            if (
                managed_object.sync_strategy == SyncStrategy.ALLOW_ADDS
                and managed_object.is_dir
                and not managed_object.in_sync
                and managed_object.validated_remote_crc == managed_object.remote_crc
            ):
                continue

            if (
                managed_object.sync_strategy == SyncStrategy.ENSURE_CREATED
                and managed_object.is_dir
                and managed_object.remote_object_exists
            ):
                continue

            if (
                managed_object.is_dir
                and managed_object.is_empty_dir()
                and managed_object.local_crc == managed_object.remote_crc
            ):
                continue

            if not managed_object.in_sync and managed_object.is_dir:
                await self.resolve_directory_state(managed_object, agent_proxy)

            if not managed_object.in_sync and not managed_object.is_dir:
                print("RESOLVE FILE STATE", managed_object)
                await self.resolve_file_state(managed_object, agent_proxy)

    def poll_all_agents(self):
        self.keeper.loop.run_until_complete(self.run_agent_tasks())

    @manage_transport
    async def enroll_agent(self, agent: RPCClient):
        log.info(f"Enrolling agent {agent.id}")
        proxy = agent.get_proxy()
        res = await proxy.generate_csr()
        csr_bytes = res.get("csr")

        csr = cryptography.x509.load_pem_x509_csr(csr_bytes)
        hostname = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        try:
            cert = self.keeper.ca.load_certificate(hostname)
            self.keeper.ca.revoke_certificate(hostname)
        except OwnCAInvalidCertificate:
            pass
        finally:
            # ToDo: there has to be a better way (don't delete cert)
            # start using CRL? Do all nodes need CRL - probably
            shutil.rmtree(f"ca/certs/{hostname}", ignore_errors=True)
            cert = self.keeper.ca.sign_csr(csr, csr.public_key())

        # This triggers agent to update registrar, it should probably
        # be it's own action
        await proxy.install_cert(cert.cert_bytes)
        await proxy.install_ca_cert(self.keeper.ca.cert_bytes)

        # proxy.one_way = True
        proxy.notify()
        await proxy.upgrade_to_ssl()
        # proxy.one_way = False

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
                self.add(flux_agent)

    def create_agent(
        self,
        address: str,
        proxy_target: str | None = None,
        auth_provider: SignatureAuthProvider | None = None,
    ) -> RPCClient:
        transport = EncryptedSocketClientTransport(
            address,
            self.app_config.comms_port,
            auth_provider=auth_provider,
            proxy_target=proxy_target,
            proxy_port=self.app_config.comms_port,
            proxy_ssl=False,
            cert=self.keeper.cert,
            key=self.keeper.key,
            ca=self.keeper.ca_cert,
            on_pty_data_callback=self.keeper.gui.pty_output,
            on_pty_closed_callback=self.keeper.gui.pty_closed,
        )
        flux_agent = RPCClient(
            JSONRPCProtocol(), transport, (self.app_config.name, address, proxy_target)
        )

        return flux_agent

    async def run_agent_tasks(self, tasks: list[Callable] = []):
        if not self.agents:
            log.info("No agents found... nothing to do")
            return

        # headless mode
        # ToDo: add cli `tasks` thingee
        if not tasks:
            tasks = [
                self.enroll_subordinates,
                self.sync_objects,
                self.get_state,
            ]

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
            except FluxVaultKeyError as e:
                log.error(f"Exception from gather tasks: {repr(e)}")
                if self.keeper.gui:
                    await self.keeper.gui.set_toast(repr(e))

        if self.keeper.gui:
            await self.keeper.gui.app_state_update(
                self.app_config.name, self.network_state
            )

    def __getattr__(self, name: str) -> Callable:
        try:
            func = self.extensions.get_method(name)
        except MethodNotFoundError as e:
            raise AttributeError(f"Method does not exist: {e}")

        if func.pass_context:
            context = FluxVaultContext(self.agents)
            func = functools.partial(func, context)

        return func
