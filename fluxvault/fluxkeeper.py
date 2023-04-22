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
import time
from contextlib import asynccontextmanager

import itertools
import aiofiles

# 3rd party
import aiohttp
import cryptography
import yaml
from cryptography.x509.oid import NameOID

# from rich.pretty import pretty_repr
# from pprint import pformat
from fluxrpc.auth import SignatureAuthProvider
from fluxrpc.client import RPCClient, RPCProxy
from fluxrpc.exc import MethodNotFoundError
from fluxrpc.protocols.jsonrpc import JSONRPCProtocol
from fluxrpc.transports.socket.client import EncryptedSocketClientTransport
from fluxrpc.transports.socket.symbols import NO_SOCKET, PROXY_NO_SOCKET
from ownca import CertificateAuthority
from ownca.exceptions import OwnCAInvalidCertificate
from rich.pretty import pprint, pretty_repr
from rich.align import Align

# this package
from fluxvault.app_init import setup_filesystem_and_wallet
from fluxvault.constants import WWW_ROOT
from fluxvault.fluxapp import (
    FluxApp,
    FluxComponent,
    # FluxTask,
    FsEntryStateManager,
    FsStateManager,
    RemoteStateDirective,
)
from fluxvault.fluxkeeper_gui import FluxKeeperGui
from fluxvault.helpers import (
    AppMode,
    NodeContactState,
    StateTransition,
    FluxVaultKeyError,
    SyncStrategy,
    FluxVaultContext,
    FluxTask,
    AgentId,
    HitCounter,
    UnixTime,
    bytes_to_human,
    manage_transport,
)
from fluxvault.log import log

CONFIG_NAME = "config.yaml"

# path types
#                  absolute  | relative | relative      | absolute
# full_fake_root = vault_dir / app_dir  / fake_root_dir / remote_dir
# app_dir is portable
# The only common format is absolute_remote
# only way to convert back and forward is with managed_object


class FluxKeeper:
    """Runs in your protected environment. Provides runtime
    data to your vulnerable services in a secure manner

    The end goal is to be able to secure an application's private data where visibility
    of that data is restricted to the application owner
    """

    # GUI hidden via cli, no where near ready, look at just breaking out console first
    def __init__(
        self,
        vault_dir: str | None = None,
        apps: FluxApp | None = None,
        # gui: bool = False,
    ):
        # ToDo: configurable port
        self.gui = FluxKeeperGui("127.0.0.1", 7777, self)

        self.loop = asyncio.get_event_loop()
        self.managed_apps: list[FluxAppManager] = []
        self.root_dir: Path = setup_filesystem_and_wallet()

        self.qualify_vault_dir(vault_dir)
        self.apps: list[FluxApp] = []

        # Allow apps to be passed in, otherwise - look up config
        for app in apps:
            if isinstance(app, FluxApp):
                self.apps.append(app)

        if not self.apps:
            for app_dir in self.vault_dir.iterdir():
                if not app_dir.is_dir():
                    continue

                try:
                    with open(app_dir / CONFIG_NAME, "r") as stream:
                        try:
                            config = yaml.safe_load(stream)
                        except yaml.YAMLError as e:
                            raise ValueError(
                                f"Error parsing vault config file: {CONFIG_NAME} for app {app_dir}. Exc: {e}"
                            )
                except (FileNotFoundError, PermissionError) as e:
                    log.error(
                        f"Error opening config file {CONFIG_NAME} for app {app_dir}. Exc: {e}"
                    )
                    continue

                self.apps.append(
                    self.build_app(app_dir.name, self.vault_dir / app_dir.name, config)
                )

        log.info(f"App Data directory: {self.root_dir}")
        log.info(f"Global Vault directory: {self.vault_dir}")
        log.info(f"Apps loaded: {[x.name for x in self.apps]}")

        self.init_certificate_authority()
        self.configure_apps()

        # if gui:
        #     self.start_gui()

    @classmethod
    def setup(cls) -> Path:
        return setup_filesystem_and_wallet()

    def qualify_vault_dir(self, dir: str):
        """Sets the vault_dir attr"""
        if not dir:
            vault_dir = Path().home() / ".vault"
        else:
            vault_dir = Path(dir)

        if not vault_dir.is_absolute():
            raise ValueError(f"Invalid vault dir: {vault_dir}, must be absolute")

        if not vault_dir.is_dir():
            vault_dir.mkdir(parents=True)

        self.vault_dir = vault_dir

    @classmethod
    def state_directives_builder(
        cls, local_relative: Path, remote_workdir: Path, fs_entries: list
    ) -> list:
        state_directives = []
        for fs_entry in fs_entries:
            parent = None
            name = fs_entry.get("name", None)

            if content_source := fs_entry.get("content_source", None):
                content_source = Path(content_source)
                name = content_source.name
                parent = content_source.parent
            else:
                # this is debatable, maybe simplier just to make it if you
                # want to manipulate a files location in the tree, you must
                # supply the content source.

                # try the root of the staging dir
                parent = local_relative

            if remote_dir := fs_entry.get("remote_dir"):
                if Path(remote_dir).is_absolute():
                    absolute_dir = Path(remote_dir)
                else:
                    absolute_dir = remote_workdir / remote_dir
            else:
                absolute_dir = remote_workdir

            sync_strategy = SyncStrategy[
                fs_entry.get("sync_strategy", SyncStrategy.ENSURE_CREATED.name)
            ]

            state_directive = RemoteStateDirective(
                name, parent, absolute_dir, sync_strategy
            )

            state_directives.append(state_directive)
        return state_directives

    # do this as a lambda?
    # flux_tasks = []
    # map(lambda x: flux_tasks.append(FluxTask(x.get("name"), x.get("params"))), tasks)
    # @classmethod
    # def tasks_builder(cls, tasks: list) -> list:
    #     flux_tasks = []
    #     for task in tasks:
    #         flux_task = FluxTask(task.get("name"), task.get("params"))
    #         flux_tasks.append(flux_task)
    #     return flux_tasks

    @classmethod
    def build_app(cls, name: str, app_dir: str, config: dict) -> FluxApp:
        log.info(f"User config:\n")
        pprint(config)
        print()

        app_config = config.get("app_config")
        groups_config = app_config.pop("groups", None)

        app = FluxApp(name, root_dir=app_dir, **app_config)

        components_config = config.get("components", {})

        for component_name, directives in components_config.items():
            remote_workdir = directives.pop("remote_workdir")

            if not Path(remote_workdir).is_absolute():
                raise ValueError(f"Remote workdir {remote_workdir} is not absolute")

            # if app.app_mode == AppMode.FILESERVER:
            #     local_workdir = app_dir
            # else:
            local_workdir = app_dir / "components" / component_name

            # this is if the content source doesn't exist... we try here
            relative_dir = Path("components") / component_name / "staging"

            component = FluxComponent(
                component_name,
                local_workdir=local_workdir,
                remote_workdir=Path(remote_workdir),
            )

            # add the members to the component, then fix up build_catalogue

            # ummmmm lol
            if groups := directives.pop("member_of", None):
                component.add_groups(groups)
                for group in groups:
                    if g := groups_config.get(group, None):
                        if d := g.get("state_directives", None):
                            if directives.get("state_directives", None):
                                directives["state_directives"].extend(d)
                            else:
                                directives["state_directives"] = d

            for directive, data in directives.items():
                match directive:
                    case "state_directives":
                        component.state_manager.add_directives(
                            FluxKeeper.state_directives_builder(
                                relative_dir, Path(remote_workdir), data
                            )
                        )
                    case "tasks":
                        component.add_tasks(FluxKeeper.tasks_builder(data))
            app.add_component(component)

        log.info("Built app config:\n")
        pprint(app)
        print()
        return app

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
        for app in self.apps:
            # if app.app_mode == AppMode.FILESERVER:
            #     app.build_fs()
            # else:
            app.build_catalogue()
            app.validate_local_objects()
            flux_app = FluxAppManager(self, app)
            self.managed_apps.append(flux_app)

    def start_gui(self):
        self.loop.run_until_complete(self.gui.start())

    def cleanup(self):
        log.info("Fluxkeeper cleanup called...")
        for app in self.apps:
            app.remove_catalogue()

        for app in self.managed_apps:
            app.cleanup()

    def get_app_manager_by_name(self, name: str) -> FluxAppManager:
        return next(filter(lambda x: x.app.name == name, self.managed_apps), None)

    async def manage_apps(self, run_once: bool, polling_interval: int):
        tasks = []

        async def manage(app_manager: FluxAppManager):
            while True:
                await app_manager.run_agents_async()

                if run_once:
                    break
                log.info(
                    f"sleeping {polling_interval} seconds for app {app_manager.app.name}..."
                )
                await asyncio.sleep(polling_interval)

        for app_manager in self.managed_apps:
            await app_manager.start_polling_fluxnode_ips()
            tasks.append(asyncio.create_task(manage(app_manager)))

        await asyncio.gather(*tasks)


class FluxAppManager:
    def __init__(
        self,
        keeper: FluxKeeper,
        app: FluxApp,
    ):
        self.keeper = keeper
        self.app = app
        self.agents: list[RPCClient] = []
        self.network_state = {}
        # make network_state proper object and move last_row_build_somewhere there
        self.last_row_build: UnixTime = 0
        self.table_rows: list[str] = []
        # move to running tasks?
        self.fluxnode_sync_task: asyncio.Task | None = None
        self.running_tasks: dict[AgentId, list[asyncio.Task]] = {}
        self.sessions: dict[AgentId, list] = {}

        # This shouldn't be here, should be on the app
        if not self.app.signing_key and self.app.sign_connections:
            raise ValueError("Signing key must be provided if signing connections")

        self.register_extensions()

    def __iter__(self):
        yield from self.agents

    def __len__(self):
        return len(self.agents)

    @property
    def agent_ids(self) -> list:
        return [x.id for x in self.agents]

    @property
    def agent_ips(self) -> set:
        return set([x[1] for x in self.agent_ids])

    @property
    def primary_agents(self) -> filter:
        # return [x for x in self.agents if not x.is_proxied]
        return list(filter(lambda x: not x.is_proxied, self.agents))

    @staticmethod
    async def get_fluxnode_ips(app_name: str) -> list:
        url = f"https://api.runonflux.io/apps/location/{app_name}"
        timeout = aiohttp.ClientTimeout(connect=10)
        retries = 3

        data = {}

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
        if data.get("status", None) == "success":
            nodes = data.get("data")
            for node in nodes:
                ip = node["ip"].split(":")[0]
                node_ips.append(ip)
        else:
            log.error("Return status from Flux api was not successful for agent IPs")

        return node_ips

    @staticmethod
    def pad_to_width(target: list, width: int) -> Align:
        """Convience function to pre-pad a list of strings
        before passing to rich Align"""

        length = len(target)

        if length < width:
            target_filler = ["  "] * (width - length)
            target = [*target, *target_filler]

        return Align.center("".join(target))

    @staticmethod
    def add_symbol_to_list(
        subject: bool,
        target: list,
        insert_loc: int | None = None,
        colors: str = "red_green",
    ):
        """Append or insert different box colors based on truthiness"""
        green_box = "\U0001F7E9"  # True
        red_box = "\U0001F7E5"  # False
        yellow_box = "\U0001F7E8"  # True
        blue_box = "\U0001F7E6"  # False
        black_box = "\U00002B1B"  # None

        if colors == "red_green":
            output = green_box if subject else red_box

        elif colors == "blue_yellow":
            output = yellow_box if subject else blue_box
        else:
            output = "XX"

        # was getting false negatives with int
        if isinstance(insert_loc, int):
            target.insert(insert_loc, output)
        else:
            target.append(output)

    #   MODIFY APPEND METHOD FOR TRUE FALSE TO ADD SYMBOLS BINARY DEQUE (2 OPTIONS)

    def get_hit_counters(self) -> dict[str, HitCounter]:
        contact_states: dict[str, NodeContactState] = {
            k[1]: v.get("contact_state") for k, v in self.network_state.items()
        }

        return {k: v.hit_counter for k, v in contact_states.items() if v}

    def cache_or_build_table_rows(self, use_cache: bool) -> list:
        if not use_cache:
            return self.build_table_rows()
        else:
            hit_counters = self.get_hit_counters()

            latest = max(hit_counters.values(), key=lambda x: x.last_update, default=0)
            if latest:
                latest = latest.last_update

            if latest > self.last_row_build:
                self.last_row_build = latest
                return self.build_table_rows()
            else:
                return self.table_rows

    def build_table_rows(self) -> list:
        rows = []

        width = 15
        for target, hit_counter in self.get_hit_counters().items():
            one_sec_column = []
            one_min_column = []
            fifteen_min_column = []
            one_hour_column = []

            for ping in list(reversed(hit_counter.one_minute)):
                self.add_symbol_to_list(ping, one_min_column)

            for ping in list(reversed(hit_counter.fifteen_minute)):
                self.add_symbol_to_list(ping, fifteen_min_column)

            for ping in list(reversed(hit_counter.one_hour)):
                self.add_symbol_to_list(ping, one_hour_column)

            length = len(hit_counter.raw)
            match length // width:
                case x if x >= width:
                    four_sec_blocks = width
                    one_sec_blocks = 0
                case x if x < width:
                    if length <= width:
                        four_sec_blocks = 0
                        one_sec_blocks = width
                    else:
                        extra = length - width
                        # we have to also take into the account the realestate we loose
                        # from converting a one column to a 4 column. The net gain is 3
                        four_sec_blocks = extra // 3
                        if extra % 3 != 0:
                            four_sec_blocks += 1

                        one_sec_blocks = width - four_sec_blocks

            if not four_sec_blocks:
                for ping in reversed(hit_counter.raw):
                    self.add_symbol_to_list(ping, one_sec_column, colors="blue_yellow")
            else:
                fifo_pings = list(reversed(hit_counter.raw))
                # get the newest first
                for ping in fifo_pings[0:one_sec_blocks]:
                    self.add_symbol_to_list(ping, one_sec_column, colors="blue_yellow")

                # aggregate the one sec blocks to four sec blocks
                for i in range(four_sec_blocks):
                    # these are the oldest first
                    start = i * 4
                    blocks = list(itertools.islice(hit_counter.raw, start, start + 4))
                    last_4: bool = all(blocks)

                    self.add_symbol_to_list(last_4, one_sec_column, one_sec_blocks)

            rows.append(
                [
                    target,
                    self.pad_to_width(one_sec_column, width),
                    self.pad_to_width(one_min_column, width),
                    self.pad_to_width(fifteen_min_column, width),
                    self.pad_to_width(one_hour_column, width),
                ]
            )
        # cache
        self.table_rows = rows
        return rows

    def cancel_and_delete_tasks(self, agent_id: tuple):
        for task in self.running_tasks[agent_id]:
            task.cancel()

        del self.running_tasks[agent_id]

    def is_task_running_for_agent(self, agent_id: tuple, task_name: str) -> bool:
        found = False
        if agent_id in self.running_tasks:
            found = bool(
                next(
                    filter(
                        lambda x: x.get_name() == task_name,
                        self.running_tasks[agent_id],
                    ),
                    False,
                ),
            )
        return found

    async def start_polling_fluxnode_ips(self):
        """Idempotent polling of Fluxnodes"""
        if not self.fluxnode_sync_task:
            self.fluxnode_sync_task = asyncio.create_task(self.build_agents())

        while not self.agents:
            await asyncio.sleep(0.1)

    def add(self, agent: RPCClient):
        self.agents.append(agent)

    def remove(self, ip: str):
        remaining = []
        # there should only ever be one app running on a host
        for agent in self.agents:
            if agent.id[1] == ip:
                self.cancel_and_delete_tasks(agent.id)
            else:
                remaining.append(agent)

        self.agents = remaining

    async def disconnect_agent_by_id(self, id: AgentId):
        if agent := self.get_agent_by_id(id):
            await agent.transport.disconnect()

    def get_agent_by_id(self, id: AgentId):
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

    def cleanup(self):
        self.fluxnode_sync_task.cancel()

    async def build_agents(self):
        while True:
            log.info("Fetching Fluxnode addresses...")
            fluxnode_ips = (
                self.app.fluxnode_ips
                if self.app.fluxnode_ips
                else await self.get_fluxnode_ips(self.app.name)
            )

            fluxnode_ips = set(fluxnode_ips)

            if not fluxnode_ips:  # error fetching ips from api
                log.error("Error fetching Fluxnode IPs... trying again in 30s")
                # try again soon
                await asyncio.sleep(30)
                continue

            missing = fluxnode_ips - self.agent_ips
            extra = self.agent_ips - fluxnode_ips

            for ip in extra:
                self.remove(ip)

            # this is stupid too. Theyre all getting the same auth provider anyway,
            # it only matters on the agent (they store stuff on the provider)
            auth_provider = None
            if self.app.sign_connections and self.app.signing_key:
                auth_provider = SignatureAuthProvider(key=self.app.signing_key)

            # this seems pretty broken
            if self.app.app_mode == AppMode.SINGLE_COMPONENT:
                component_name = self.app.get_component().name
            else:
                component_name = "fluxagent"

            try:
                for ip in missing:
                    agent_id = (self.app.name, ip, component_name)
                    self.network_state[agent_id] = {}

                    transport = EncryptedSocketClientTransport(
                        ip,
                        self.app.comms_port,
                        auth_provider=auth_provider,
                        proxy_target="",
                        on_pty_data_callback=self.keeper.gui.pty_output,
                        on_pty_closed_callback=self.keeper.gui.pty_closed,
                        rekey_timer=60,
                    )
                    flux_agent = RPCClient(JSONRPCProtocol(), transport, agent_id)
                    self.add(flux_agent)
                    log.info(f"Agent {flux_agent.id} added...")
            except Exception as e:
                print(repr(e))

            # if addresses were passed in, we don't need to loop
            if self.app.fluxnode_ips:
                break

            await asyncio.sleep(60)

    def register_extensions(self):
        self.app.extensions.add_method(self.get_all_agents_methods)
        self.app.extensions.add_method(self.poll_all_agents)

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.app.extensions.method_map.items()}

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
        self.network_state[agent.id].update(await proxy.get_state())

    @staticmethod
    def get_extra_objects(
        app_mode: AppMode,
        managed_object: FsEntryStateManager,
        local_hashes: dict[str, int],
        remote_hashes: dict[str, int],
    ) -> tuple[list[Path], int]:
        count = 0
        extras = []

        fake_root = managed_object.root()

        root_path = "/"
        for remote_name in remote_hashes:
            remote_name = Path(remote_name)

            target = str(fake_root / remote_name.relative_to(root_path))
            exists = local_hashes.get(target, None)

            if exists == None:
                count += 1
                if not extras:
                    extras.append(remote_name)

                extras = FsStateManager.filter_hierarchy(remote_name, extras)

        return (extras, count)

    @staticmethod
    def get_missing_or_modified_objects(
        app_mode: AppMode,
        managed_object: FsEntryStateManager,
        local_hashes: dict[str, int],
        remote_hashes: dict[str, int],
    ) -> tuple[list[Path], int, int]:
        # can't use zip here as we don't know remote lengths
        # set would work for filenames but not hashes
        # iterate hashes and find missing / modified objects

        missing = 0
        modified = 0
        candidates: list[Path] = []
        fake_root = managed_object.root()

        # if app_mode == AppMode.FILESERVER:
        #     remote_root = managed_object.remote_workdir
        # else:
        remote_root = "/"

        for local_path, local_crc in local_hashes.items():
            local_path = Path(local_path)

            remote_absolute = remote_root / local_path.relative_to(fake_root)

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
        managed_object: FsEntryStateManager,
        local_hashes: dict[str, int],
        remote_hashes: dict[str, int],
    ) -> tuple[list[Path], list[Path]]:
        candidates, missing, modified = self.get_missing_or_modified_objects(
            self.app.app_mode, managed_object, local_hashes, remote_hashes
        )

        extra_objects, unknown = self.get_extra_objects(
            self.app.app_mode, managed_object, local_hashes, remote_hashes
        )

        log.info(
            f"{missing} missing object(s), {modified} modified object(s) and {unknown} extra object(s)"
        )

        return (candidates, extra_objects)

    async def sync_remote_object(
        self,
        agent_proxy: RPCProxy,
        managed_object: FsEntryStateManager,
        object_fragments: list[Path] = [],
    ) -> dict:
        MAX_INBAND_FILESIZE = 1048576 * 50
        inband = False
        to_stream = []

        # this whole thing needs a refactor, gets called for both files and dirs
        # whole fragment thing is weird
        if object_fragments:
            remote_dir = managed_object.absolute_remote_path
            # think this is broken
            size = managed_object.concrete_fs.get_partial_size(object_fragments)
        else:
            remote_dir = managed_object.absolute_remote_dir
            object_fragments = [managed_object.concrete_fs.path]
            size = managed_object.concrete_fs.size

        # this logging is wrong. It implies that each object is the size which isn't correct
        # It's the aggregate size of all children if it's a dir and the size if it's a file
        #
        # log.info(
        #     f"Sending {bytes_to_human(size)} across {len(object_fragments)} object(s)"
        # )

        if size < MAX_INBAND_FILESIZE:
            inband = True

        for fs_entry in object_fragments:
            # this is dumb, but I'm tired. Ideally shouldn't be creating parent dirs
            # for files on remote end - they should get created explictily

            # this is true except for root dir, it's "fake root"
            # if syncing_root:
            #     # need to fake this
            #     abs_remote_path = str(remote_dir / managed_object.name)
            # else:
            #     print("RELATIVE", fs_entry, managed_object.local_path)
            if fs_entry != managed_object.local_parent / managed_object.name:
                relative = fs_entry.relative_to(
                    managed_object.local_parent / managed_object.name
                )
                abs_remote_path = str(remote_dir / relative)
            else:
                abs_remote_path = str(remote_dir / fs_entry.name)

            if fs_entry.is_dir():
                # Only need to do for empty dirs but currently doing on all dirs (wasteful as they will get created anyways)
                await agent_proxy.write_object(abs_remote_path, True, b"")
            elif fs_entry.is_file():
                # read whole file in one go as it's less than 50Mb
                if inband:
                    async with aiofiles.open(fs_entry, "rb") as f:
                        await agent_proxy.write_object(
                            abs_remote_path, False, await f.read()
                        )
                    continue
                else:
                    to_stream.append((fs_entry, abs_remote_path))
        if to_stream:
            transport = agent_proxy.get_transport()
            await transport.stream_files(to_stream)

    async def resolve_file_state(
        self, managed_object: FsEntryStateManager, agent_proxy: RPCProxy
    ):
        log.info(
            f"File {managed_object.name} with size {bytes_to_human(managed_object.concrete_fs.size)} is about to be transferred"
        )
        # this seems a bit strange but writing directory uses the same interface
        # and they don't know who the file names are, the just have the associated
        # managed_object

        # what are we passing in here?
        await self.sync_remote_object(agent_proxy, managed_object)

        managed_object.in_sync = True
        managed_object.remote_object_exists = True

    async def resolve_directory_state(
        self,
        component: FluxComponent,
        managed_object: FsEntryStateManager,
        agent_proxy: RPCProxy,
    ) -> list:
        remote_path = str(managed_object.absolute_remote_path)

        # if it doesn't exist - no point getting child hashes
        if managed_object.remote_crc == 0:
            await self.sync_remote_object(agent_proxy, managed_object)
            return []

        # this is different from the global get_all_object_hashes - this adds
        # all the hashes together, get_directory_hashes keeps them seperate
        remote_hashes = await agent_proxy.get_directory_hashes(remote_path)
        # these are absolute
        local_hashes = managed_object.concrete_fs.get_directory_hashes(
            name=managed_object.name
        )

        # these are in remote absolute form
        object_fragments, objects_to_remove = self.resolve_object_deltas(
            managed_object, local_hashes, remote_hashes
        )

        if (
            managed_object.remit.sync_strategy == SyncStrategy.STRICT
            and objects_to_remove
        ):
            # we need to remove extra objects
            # ToDo: sort serialization so you can pass in paths etc
            to_delete = [str(x) for x in objects_to_remove]
            await agent_proxy.remove_objects(to_delete)
            log.info(
                f"Sync strategy set to {SyncStrategy.STRICT.name} for {managed_object.name}, deleting extra objects: {to_delete}"
            )
        elif SyncStrategy.ALLOW_ADDS:
            managed_object.validated_remote_crc = managed_object.remote_crc

        log.info(
            f"Deltas resolved... {len(object_fragments)} object(s) need to be resynced"
        )

        if object_fragments:
            await self.sync_remote_object(agent_proxy, managed_object, object_fragments)
            component.state_manager.set_syncronized(object_fragments)

        managed_object.in_sync = True
        managed_object.remote_object_exists = True

        return object_fragments

    @manage_transport
    async def load_manifest(self, agent: RPCClient):
        """This is solely for the fileserver"""

        if not agent.transport.auth_provider:
            log.warn("Agent not using auth, unable to sign manifest... skipping")
            return

        component = self.app.get_component(agent.id[2])
        managed_object = component.state_manager.get_object_by_remote_path(WWW_ROOT)
        fileserver_hash = managed_object.local_crc
        # this only works if we're signing messages
        sig = agent.transport.auth_provider.sign_message(str(fileserver_hash))
        # manifest = managed_object.concrete_fs.decendants()
        agent_proxy = agent.get_proxy()
        await agent_proxy.load_manifest(fileserver_hash, sig)

    @manage_transport
    async def sync_objects(self, agent: RPCClient):
        log.debug(f"Contacting Agent {agent.id} to check if files required")
        # ToDo: fix formatting nightmare between local / common / remote
        component = self.app.get_component(agent.id[2])

        if not component:
            # each component must be specified
            log.warn(
                f"No config found for component {agent.id[2]}, this component will only get globally specified files"
            )
            return

        remote_paths = component.state_manager.absolute_remote_paths()

        agent_proxy = agent.get_proxy()

        # start = time.monotonic()
        remote_fs_objects = await agent_proxy.get_all_object_hashes(remote_paths)
        # elapsed = time.monotonic() - start
        # log.info(f"Time to get hashes: {round(elapsed, 4)}")

        log.debug(f"Agent {agent.id} remote file CRCs: {remote_fs_objects}")

        if not remote_fs_objects:
            log.warn(f"No objects to sync for {agent.id} specified... skipping!")
            return

        fixed_objects = []

        for remote_fs_object in remote_fs_objects:
            # this is broken. If we're a dir, any children have already been fixed. Don't
            # need to resolve them too. So need to keep track of the parent.
            remote_path = Path(remote_fs_object["name"])
            managed_object = component.state_manager.get_object_by_remote_path(
                remote_path
            )

            if managed_object.local_path in fixed_objects:
                managed_object.remote_crc = managed_object.local_crc
                return

            if not managed_object:
                log.warn(f"managed object: {remote_path} not found in component config")
                return

            managed_object.remote_crc = remote_fs_object["crc32"]
            # this just crc's the local object, I had this disabled so only validate files
            # on boot but meh - disabled again, it's fucking slow and blocking my shit, tried in a thread
            # but the expensive of shunting to a thread is probably too much. I should probably split this whole
            # function from sync / async and run in thread
            # await asyncio.to_thread(managed_object.validate_local_object)
            managed_object.compare_objects()

            if not managed_object.local_object_exists:
                log.warn(
                    f"Remote object exists but local doesn't: {managed_object.local_path}. Local workdir: {managed_object.local_workdir}"
                )
                continue

            if (
                managed_object.remit.sync_strategy == SyncStrategy.ALLOW_ADDS
                and managed_object.concrete_fs.storable
                and not managed_object.in_sync
                and managed_object.validated_remote_crc == managed_object.remote_crc
            ):
                continue

            if (
                managed_object.remit.sync_strategy == SyncStrategy.ENSURE_CREATED
                # and managed_object.concrete_fs.storable
                and managed_object.remote_object_exists
            ):
                continue

            if (
                managed_object.concrete_fs.storable
                and managed_object.concrete_fs.empty
                and managed_object.local_crc == managed_object.remote_crc
            ):
                continue

            if not managed_object.in_sync and managed_object.concrete_fs.storable:
                # so here we need to figure any children dirs and set them manually to in_sync
                fixed = await self.resolve_directory_state(
                    component, managed_object, agent_proxy
                )
                fixed_objects.extend(fixed)

            if not managed_object.in_sync and not managed_object.concrete_fs.storable:
                await self.resolve_file_state(managed_object, agent_proxy)

        # log.info(f"Time to sync objects: {time.monotonic() - start}")

    def poll_all_agents(self):
        self.keeper.loop.run_until_complete(self.run_agent_tasks())

    @manage_transport
    async def load_agent_plugins(self, agent: RPCClient):
        agent_proxy = agent.get_proxy()
        await agent_proxy.load_plugins()

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

    def get_task_state(self) -> dict:
        all_agents = {k.id: [] for k in list(self.agents)}
        all_tasks = {
            k: [x.get_name() for x in v] for k, v in self.running_tasks.items()
        }
        all_agents.update(all_tasks)
        # build data model for ping stuff
        # this function should just add to network_state

    @staticmethod
    async def wait_for_events(events: list[asyncio.Event]):
        """Await each event, this ensures all events have completed"""
        for event in events:
            await event.wait()

    async def ping_all_nodes(
        self, down_callback: Callable, up_callback: Callable, interval: int = 1
    ):
        sync_events: list[asyncio.Event] = []

        for agent in self.agents:
            sync_event = asyncio.Event()
            sync_events.append(sync_event)
            agent_tasks = self.running_tasks.get(agent.id, [])

            ping_task = next(
                filter(lambda x: x.get_name() == "ping", agent_tasks), None
            )
            if not ping_task:
                t = asyncio.create_task(
                    self.ping_pong(
                        agent,
                        interval=interval,
                        down_callback=down_callback,
                        up_callback=up_callback,
                        sync_event=sync_event,
                    ),
                    name="ping",
                )
                if agent.id not in self.running_tasks:
                    self.running_tasks[agent.id] = [t]
                else:
                    self.running_tasks[agent.id].append(t)

        # this needs a timeout
        await self.wait_for_events(sync_events)

    @manage_transport(exclusive=True)
    async def ping_pong(
        self,
        agent: RPCClient,
        interval: int,
        down_callback: Callable,
        up_callback: Callable,
        sync_event: asyncio.Event,
    ):
        """Ping node once every interval seconds. This interval includes the RTT of the ping,
        if the RTT exceeds the interval, it is pinged again immediately. If the nodes
        missed 3 pings (intervals) or doesn't respond with the correct PONG - the user provided
        callback is called and we stop pinging"""

        # we are saying we have connected (decorator has run)
        sync_event.set()

        state = NodeContactState()
        self.network_state[agent.id].update({"contact_state": state})
        agent_proxy = agent.get_proxy(exclusive=True)

        async def run_callback(callback) -> bool:
            # this_task = next(
            #     filter(
            #         lambda x: x.get_name() == "ping",
            #         self.running_tasks[agent.id],
            #     )
            # )

            # self.running_tasks[agent.id].remove(this_task)

            if asyncio.iscoroutinefunction(callback):
                await callback(agent.id)
            else:
                callback(agent.id)

            # this_task.cancel()

        async def ping_forever():
            # logic
            DOWN_NODE_INTERVAL = interval * 10
            QUARANTINE_TIMER = 300
            # if 3 missed in a row... you're out of here
            # if 6 missed in a one minute period... you're out of here
            consecutive_misses = 0
            while True:
                # switch back to monotonic for those gainz
                start = time.perf_counter()
                try:
                    # we need shield here, if we don't and we timeout, the task gets cancelled,
                    # which stops the transport pulling the message off the queue; depending on where we
                    # # hit the timeout. So we could have an extra
                    # message in there, which gets returned immediately, making it look like the
                    # elapsed time is very, very, short
                    # However, what happens if we get 3 timeouts, do we need to cancel
                    # the tasks
                    agent_proxy.set_timeout(interval)
                    # resp = await asyncio.wait_for(
                    #     asyncio.shield(agent_proxy.ping()), timeout=interval
                    # )
                    resp = await agent_proxy.ping()
                except asyncio.TimeoutError as e:
                    state.update_hit_counter(False)
                    consecutive_misses += 1
                    log.error(
                        f"Error pinging remote: {agent.id}. Consecutive_misses: {consecutive_misses}"
                    )
                    if consecutive_misses >= 10:
                        consecutive_misses = 0
                        await agent.transport.disconnect()
                        try:
                            await agent.transport.ensure_connected()
                        except Exception as e:
                            print("orangutan")
                            print(repr(e))
                        continue

                    elif consecutive_misses >= 4 or state.one_minute_miss_count >= 8:
                        if state.active:
                            state.transitions.append(StateTransition(False))
                            await run_callback(down_callback)

                    else:
                        state.increment_counters()

                except (ConnectionResetError, BrokenPipeError) as e:
                    log.error(f"Agent: {agent.id} disconnected with E: {repr(e)}")
                    state.increment_counters()
                    consecutive_misses = 0
                    await agent.transport.disconnect()
                    if state.active:
                        state.transitions.append(StateTransition(False))
                        await run_callback(down_callback)
                    try:
                        await agent.transport.ensure_connected()
                    except Exception as e:
                        print("giraffe")
                        print(repr(e))

                except Exception as e:
                    print(f"Exiting ping forever: {repr(e)}")
                    exit(1)
                else:
                    rtt = time.monotonic() - start
                    try:
                        state.update_rtt(rtt)
                        state.update_hit_counter(True)
                    except Exception as e:
                        print(repr(e))

                    consecutive_misses = 0
                    if resp != "PONG":
                        log.warning(f"Received incorrect ping response: {resp}")

                    if not state.active and not state.in_quarantine:
                        log.info(
                            f"Node resumed... putting into quarantine for 300 seconds"
                        )
                        state.transitions.append(StateTransition(True))
                        state.quarantine()

                    elif state.in_quarantine:
                        if (
                            start - state.quarantine_timer > QUARANTINE_TIMER
                            and state.one_minute_miss_count < 6
                        ):
                            log.info(f"Node has passed quarantine tests... reinstating")
                            state.dequarantine()
                            await run_callback(up_callback)
                finally:
                    state.total_count += 1
                    elapsed = time.perf_counter() - start
                    # if state.total_count % 10 == 0:
                    #     print(
                    #         f"{agent.id} count: {state.total_count} elapsed: {elapsed}"
                    #     )

                    if not state.active and not state.in_quarantine:
                        timer = DOWN_NODE_INTERVAL
                    else:
                        timer = interval
                    to_sleep = max(0, timer - elapsed)
                    # print(f"To sleep: {to_sleep}")
                    await asyncio.sleep(to_sleep)

        await ping_forever()
        # pprint(asyncio.all_tasks())

    @manage_transport
    async def set_mode(self, agent: RPCClient):
        agent_proxy = agent.get_proxy()
        resp = await agent_proxy.set_mode(self.app.app_mode.value)

    # @manage_transport
    # async def enable_fileserver(self, agent: RPCClient):
    #     agent_proxy = agent.get_proxy()
    #     resp = await agent_proxy.enable_registrar_fileserver()

    @manage_transport
    async def get_agents_state(self, agent: RPCClient) -> str:
        agent_proxy = agent.get_proxy()
        resp = await agent_proxy.get_container_state()

        return resp

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
            self.app.comms_port,
            auth_provider=auth_provider,
            proxy_target=proxy_target,
            proxy_port=self.app.comms_port,
            proxy_ssl=False,
            cert=self.keeper.cert,
            key=self.keeper.key,
            ca=self.keeper.ca_cert,
            on_pty_data_callback=self.keeper.gui.pty_output,
            on_pty_closed_callback=self.keeper.gui.pty_closed,
        )
        flux_agent = RPCClient(
            JSONRPCProtocol(), transport, (self.app.name, address, proxy_target)
        )
        flux_agent.transport: EncryptedSocketClientTransport

        return flux_agent

    def set_default_tasks(self) -> list[Callable]:
        tasks = [
            self.build_task("sync_objects"),
            self.build_task("set_mode"),
            self.build_task("get_state"),
        ]

        if self.app.app_mode != AppMode.FILESERVER:
            tasks.insert(0, FluxTask("enroll_subordinates"))

        if self.app.app_mode == AppMode.FILESERVER:
            tasks.insert(2, FluxTask("load_manifest"))

        return tasks

    def build_task(
        self, name: str, args: list = [], kwargs: dict = {}
    ) -> FluxTask | None:
        try:
            func = getattr(self, name)
        except AttributeError:
            log.warn(f"Task {name} not found, skipping")
            return

        return FluxTask(name=name, args=args, kwargs=kwargs, func=func)

    async def reachable_via_proxy(self, proxy_ip: str, target_ip: str) -> bool:
        agent = self.create_agent(proxy_ip, target_ip)

        await agent.transport.connect()

        if not agent.transport.connected:
            return False

        await agent.transport.disconnect()

        return True

    @asynccontextmanager
    async def agent_sessions(self, agents: list[tuple] = []):
        if agents:
            agents = [self.get_agent_by_id(x) for x in agents]
            agents = list(filter(None, agents))
        else:
            agents = self.agents

        for agent in agents:
            await agent.transport.session.start()

        yield

        for agent in agents:
            await agent.transport.session.end()

    async def task_runner(self, agent: RPCClient, tasks: list[FluxTask]) -> dict:
        # con_kwargs = {"in_session": True}
        results = {}

        for task in tasks:
            if not task.func:
                continue

            res = await task.func(agent, *task.args, **task.kwargs, in_session=True)
            results[task.func.__name__] = res
            # let loop run something else, otherwise we hogin
            await asyncio.sleep(0.05)

        return {agent.id: results}

    async def run_session_tasks(
        self,
        tasks: list[FluxTask] = [],
        targets: dict[AgentId, list[FluxTask]] = {},
    ) -> dict[tuple, dict]:
        if not self.agents:
            log.info("No agents found... nothing to do")
            return

        if not tasks and not targets:
            tasks = self.set_default_tasks()

        agents = []
        for target, agent_tasks in targets.items():
            if agent := self.get_agent_by_id(target):
                agents.append((agent, agent_tasks))
            else:
                log.warn(f"Target {target} not found... nothing to do")

        if not agents:
            agents = [(x, tasks) for x in self.agents]

        # log.info(f"Agent session tasks: {pretty_repr(agents)}")

        coroutines = []
        for agent, tasks in agents:
            t = asyncio.create_task(self.task_runner(agent, tasks))
            coroutines.append(t)

        try:
            results = await asyncio.gather(*coroutines)
        except FluxVaultKeyError as e:
            log.error(f"Exception from gather tasks: {repr(e)}")
            if self.keeper.gui:
                await self.keeper.gui.set_toast(repr(e))

        # Going for speed gains... this takes hardly any time but trying for improvements
        # if self.keeper.gui:
        #     await self.keeper.gui.app_state_update(self.app.name, self.network_state)

        results = list(filter(None, results))
        results = reduce(lambda a, b: {**a, **b}, results)

        return results

    async def run_agents_async(
        self,
        tasks: list[FluxTask] = [],
        stay_connected: bool = False,
        already_connected: bool = False,
        targets: dict[AgentId, list[FluxTask]] = {},
        async_tasks: bool = False,  # NotImplemented
    ) -> dict[tuple, dict]:
        if not self.agents:
            log.info("No agents found... nothing to do")
            return

        if not tasks and not targets:
            tasks = self.set_default_tasks()

        coroutines = []
        print("stay connected", stay_connected)
        print("already connected", already_connected)

        async def task_runner(agent: RPCClient, tasks: list[FluxTask]) -> dict:
            length = len(tasks)
            results = {}

            for index, task in enumerate(tasks):
                # first task connects, last task disconnects

                if agent.transport.failed_on == NO_SOCKET:
                    # this is super dirty
                    agent.transport.failed_on = ""
                    # means we skip all tasks in this run but can then run
                    # again next time
                    break

                if not task.func:
                    continue

                connect = False
                disconnect = False
                if index == 0 and not already_connected:
                    connect = True
                if index + 1 == length and not stay_connected:
                    disconnect = True

                con_kwargs = {
                    "connect": connect,
                    "disconnect": disconnect,
                    "in_session": False,
                }

                # doesn't this mean you have to use @manage_transport???
                res = await task.func(agent, *task.args, **task.kwargs, **con_kwargs)
                results[task.func.__name__] = res

            # agent.id is a tuple of app.name, ip, component_name
            return {agent.id: results}

        log.info(f"Agent session tasks: {pretty_repr(targets)}")

        agents = []
        for target, agent_tasks in targets.items():
            # if not seesion.started ??? connect? Should a session encapsulate
            # an agent?
            if agent := self.get_agent_by_id(target):
                agents.append((agent, agent_tasks))
            else:
                log.warn(f"Target {target} not found... nothing to do")

        if not agents:
            agents = [(x, tasks) for x in self.agents]

        for agent, tasks in agents:
            t = asyncio.create_task(task_runner(agent, tasks))
            coroutines.append(t)

        try:
            results = await asyncio.gather(*coroutines)
        except FluxVaultKeyError as e:
            log.error(f"Exception from gather tasks: {repr(e)}")
            if self.keeper.gui:
                await self.keeper.gui.set_toast(repr(e))

        if self.keeper.gui:
            await self.keeper.gui.app_state_update(self.app.name, self.network_state)

        results = list(filter(None, results))
        results = reduce(lambda a, b: {**a, **b}, results)

        return results

    def __getattr__(self, name: str) -> Callable:
        try:
            func = self.app.extensions.get_method(name)
        except MethodNotFoundError as e:
            raise AttributeError(f"Method does not exist: {e}")

        if func.pass_context:
            context = FluxVaultContext(self.agents, self.keeper.ca)
            name = func.__name__
            func = functools.partial(func, context)
            func.__name__ = name

        return func
