from __future__ import annotations

import asyncio
import binascii
import importlib
import io
import os
import pty
import ssl
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import aiofiles
import aioshutil
from aiofiles import os as aiofiles_os
from aiohttp import ClientSession
from fluxrpc.auth import SignatureAuthProvider
from fluxrpc.protocols.jsonrpc import JSONRPCProtocol
from fluxrpc.server import RPCServer
from fluxrpc.transports.socket.server import EncryptedSocketServerTransport
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from fluxvault.extensions import FluxVaultExtensions
from fluxvault.helpers import get_app_and_component_name
from fluxvault.log import log
from fluxvault.registrar import FluxAgentRegistrar, FluxPrimaryAgent, FluxSubAgent


class FluxAgentException(Exception):
    pass


class FluxAgent:
    """Runs on Flux nodes - waits for connection from FluxKeeper"""

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        bind_port: int = 8888,
        enable_registrar: bool = False,
        registrar: FluxAgentRegistrar | None = None,
        extensions: FluxVaultExtensions = FluxVaultExtensions(),
        working_dir: str = tempfile.gettempdir(),
        whitelisted_addresses: list = ["127.0.0.1"],
        verify_source_address: bool = False,
        signed_vault_connections: bool = False,
        zelid: str = "",
        subordinate: bool = False,
        primary_agent: FluxPrimaryAgent | None = None,
    ):
        # ToDo: look at using __async__ instead of run_until_complete
        self.enable_registrar = enable_registrar
        self.extensions = extensions
        self.loop = asyncio.get_event_loop()
        self.zelid = zelid
        self.working_dir = working_dir
        self.subordinate = subordinate
        self.registrar = registrar
        self.signed_vault_connections = signed_vault_connections
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.whitelisted_addresses = whitelisted_addresses
        self.verify_source_address = verify_source_address
        self.primary_agent = primary_agent
        self.component_name, self.app_name = get_app_and_component_name()

        log.info(f"Component name: {self.component_name}, App name: {self.app_name}")

        if not self.signed_vault_connections and not self.verify_source_address:
            # Must verify source address as a minimum
            self.verify_source_address = True

        self.raise_on_state_errors()
        self.register_extensions()
        self.setup_registrar()
        self.loop.run_until_complete(self.setup_sub_agent())

        self.auth_provider = self.loop.run_until_complete(self.get_auth_provider())
        transport = EncryptedSocketServerTransport(
            bind_address,
            bind_port,
            whitelisted_addresses=whitelisted_addresses,
            verify_source_address=verify_source_address,
            auth_provider=self.auth_provider,
        )
        self.rpc_server = RPCServer(transport, JSONRPCProtocol(), self.extensions)

    @staticmethod
    async def get_app_owner_zelid(app_name: str) -> str:
        # ToDo: move this to helpers
        async with ClientSession() as session:
            async with session.get(
                f"https://api.runonflux.io/apps/appowner?appname={app_name}"
            ) as resp:
                data = await resp.json()
                zelid = data.get("data", "")
        return zelid

    async def setup_sub_agent(self):
        if self.subordinate:
            self.sub_agent = FluxSubAgent(
                self.component_name,
                self.app_name,
                self.primary_agent,
                address=self.bind_address,
            )
            await self.sub_agent.register_with_primary_agent()

    def setup_registrar(self):
        if self.enable_registrar and not self.registrar:
            self.registrar = FluxAgentRegistrar()

    def raise_on_state_errors(self):
        """Minimal tests to ensure we are good to run"""
        try:
            os.listdir(self.working_dir)
        except Exception as e:
            raise FluxAgentException(f"Error accessing working directory: {e}")

        if self.verify_source_address and not self.whitelisted_addresses:
            raise ValueError(
                "Whitelisted addresses must be provided if not signing connections"
            )

        if self.subordinate and not self.primary_agent:
            raise ValueError("Primary agent must be provided if subordinate")

    def register_extensions(self):
        self.extensions.add_method(self.get_all_object_hashes)
        self.extensions.add_method(self.write_objects)
        self.extensions.add_method(self.remove_objects)
        self.extensions.add_method(self.get_methods)
        self.extensions.add_method(self.get_subagents)
        self.extensions.add_method(self.generate_csr)
        self.extensions.add_method(self.install_cert)
        self.extensions.add_method(self.install_ca_cert)
        self.extensions.add_method(self.upgrade_to_ssl)
        self.extensions.add_method(self.load_plugins)
        self.extensions.add_method(self.list_server_details)
        self.extensions.add_method(self.connect_shell)
        self.extensions.add_method(self.disconnect_shell)
        self.extensions.add_method(self.get_state)
        self.extensions.add_method(self.get_directory_hashes)

        # self.extensions.add_method(self.run_entrypoint)
        # self.extensions.add_method(self.extract_tar)

    async def get_auth_provider(self):
        auth_provider = None
        if self.signed_vault_connections:
            # this is solely for testing without an app (outside of a Fluxnode)
            if self.zelid:
                address = self.zelid
            else:
                address = await self.get_app_owner_zelid(self.app_name)
            log.info(f"App zelid is: {address}")
            auth_provider = SignatureAuthProvider(address=address)
        return auth_provider

    def run(self):
        if self.enable_registrar:
            self.loop.create_task(self.registrar.start_app())
            log.info(
                f"Sub agent http server running on port {self.registrar.bind_port}"
            )

        task = self.loop.create_task(self.rpc_server.serve_forever())

        try:
            self.loop.run_forever()
        finally:
            task.cancel()
            if self.enable_registrar:
                self.loop.run_until_complete(self.registrar.cleanup())

    async def run_async(self):
        if self.enable_registrar:
            self.loop.create_task(self.registrar.start_app())
            log.info(
                f"Sub agent http server running on port {self.registrar.bind_port}"
            )

        self.loop.create_task(self.rpc_server.serve_forever())

    async def upgrade_to_ssl(self):
        cert = tempfile.NamedTemporaryFile()
        key = tempfile.NamedTemporaryFile()
        ca_cert = tempfile.NamedTemporaryFile()
        with open(cert.name, "wb") as f:
            f.write(self.cert)
        with open(key.name, "wb") as f:
            f.write(self.key)
        with open(ca_cert.name, "wb") as f:
            f.write(self.ca_cert)

        log.info("Upgrading connection to SSL")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert.name, keyfile=key.name)
        context.load_verify_locations(cafile=ca_cert.name)
        context.check_hostname = False
        context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
        # context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")

        cert.close()
        key.close()
        ca_cert.close()

        transport = EncryptedSocketServerTransport(
            self.bind_address,
            self.bind_port + 1,
            whitelisted_addresses=self.whitelisted_addresses,
            verify_source_address=self.verify_source_address,
            auth_provider=self.auth_provider,
            ssl=context,
        )
        await self.rpc_server.transport.stop_server()
        log.info("Non SSL RPC server stopped")
        self.rpc_server = RPCServer(transport, JSONRPCProtocol(), self.extensions)
        self.loop.create_task(self.rpc_server.serve_forever())

    def cleanup(self):
        # ToDo: look at cleanup for rpc server too
        if self.registrar:
            self.loop.run_until_complete(self.registrar.cleanup())

    def opener(self, path, flags):

        return os.open(path, flags, 0o777)

    ### EXTERNAL METHODS CALLED FROM KEEPER BELOW HERE ###

    def get_methods(self) -> dict:
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.extensions.method_map.items()}

    def get_state(self) -> dict:
        methods = self.get_methods()
        plugins = self.extensions.list_plugins()
        primary_agent = self.primary_agent.to_dict() if self.primary_agent else None
        return {
            "methods": methods,
            "plugins": plugins,
            "component_name": self.component_name,
            "app_name": self.app_name,
            "enable_registrar": self.enable_registrar,
            "zelid": self.zelid,
            "working_dir": self.working_dir,
            "subordinate": self.subordinate,
            "signed_vault_connections": self.signed_vault_connections,
            "bind_address": self.bind_address,
            "bind_port": self.bind_port,
            "whitelisted_addresses": self.whitelisted_addresses,
            "verify_source_address": self.verify_source_address,
            "primary_agent": primary_agent,
        }

    async def crc_file(self, filename: Path, crc: int) -> int:
        async with aiofiles.open(filename, "rb") as f:
            data = await f.read()
            crc = binascii.crc32(data, crc)

        return crc

    async def crc_directory(self, directory: Path, crc: int) -> int:
        crc = binascii.crc32(directory.name.encode(), crc)
        for path in sorted(directory.iterdir(), key=lambda p: str(p).lower()):
            crc = binascii.crc32(path.name.encode(), crc)

            if path.is_file():
                crc = await self.crc_file(path, crc)
            elif path.is_dir():
                crc = await self.crc_directory(path, crc)
        return crc

    async def get_object_crc(self, path: str) -> int:
        p = Path(path)

        if not p.is_absolute():
            p = self.working_dir / p

        if not p.exists():
            crc = 0

        elif p.is_dir():
            crc = await self.crc_directory(p, 0)

        elif p.is_file():
            crc = await self.crc_file(p, 0)

        return {"name": path, "crc32": crc}

    async def get_all_object_hashes(self, objects: list) -> list:
        """Returns the crc32 for each object that is being managed"""
        log.info(f"Returning crc's for {len(objects)} object(s)")
        tasks = []
        for obj in objects:
            tasks.append(self.loop.create_task(self.get_object_crc(obj)))
        results = await asyncio.gather(*tasks)
        return results

    async def get_file_hash(self, file: Path):
        crc = await self.crc_file(file, 0)
        return {str(file): crc}

    async def get_directory_hashes(self, dir: str):
        """Hashes up all files in a specific directory. if
        give relative path, out working dir is base path. Need
        to remove this again for each hash to give back common path format"""
        hashes = {}
        p = Path(dir)
        path_relative_to_workdir = False
        try:
            if not p.is_absolute():
                p = self.working_dir / p
                path_relative_to_workdir = True

            if not p.exists():
                return hashes

            crc = binascii.crc32(p.name.encode())

            hashes.update({str(p): crc})
            for path in sorted(p.iterdir(), key=lambda p: str(p).lower()):
                if path.is_dir():
                    hashes.update(await self.get_directory_hashes(str(path)))

                elif path.is_file():
                    hashes.update(await self.get_file_hash(path))

            if path_relative_to_workdir:
                hashes = {
                    str(Path(k).relative_to(self.working_dir)): v
                    for k, v in hashes.items()
                }
        except Exception as e:
            print(repr(e))
            raise

        return hashes

    async def remove_object(self, obj: str):
        p = Path(obj)

        if not p.is_absolute():
            p = self.working_dir / p

        if p.exists():
            if p.is_dir():
                await aioshutil.rmtree(p)
            elif p.is_file():
                await aiofiles_os.remove(p)

    async def write_object(self, obj: dict):
        # ToDo: brittle file path
        # ToDo: catch file PermissionError etc

        executable = False  # pass this in dict in future

        if isinstance(obj["data"], bytes):
            mode = "wb"
        elif isinstance(obj["data"], str):
            mode = "w"
        else:
            raise ValueError("Data written must be either str or bytes")

        p = Path(obj["path"])

        if not p.is_absolute():
            p = self.working_dir / p

        p.parent.mkdir(parents=True, exist_ok=True)

        # this will make the file being written executable
        opener = self.opener if executable else None

        if obj["is_dir"]:
            p.mkdir(parents=True, exist_ok=True)
            if not obj["data"]:
                return

        if obj.get("uncompressed", False):
            try:
                async with aiofiles.open(p, mode=mode, opener=opener) as file:
                    await file.write(obj["data"])
            # ToDo: tighten this up
            except Exception as e:
                log.error(repr(e))

        else:  # tarball
            fh = io.BytesIO(obj["data"])
            try:
                with tarfile.open(fileobj=fh, mode="r|bz2") as tar:
                    tar.extractall(str(p))
                return
            except Exception as e:
                print(f"Tarfile error: {repr(e)}")

    async def get_subagents(self):
        agents = {}
        if self.registrar:
            agents = {v.dns_name: v.as_dict() for v in self.registrar.sub_agents}
        return {"sub_agents": agents}

    async def write_objects(self, objects: list):
        """Will write to disk any file provided, in the format {"name": <content>}"""
        # ToDo: this should be tasks
        for obj in objects:
            log.info(f"Writing object {obj['path']}")
            await self.write_object(obj)

    async def remove_objects(self, objects: list):
        for obj in objects:
            log.info(f"Removing object {obj}")
            await self.remove_object(obj)

    async def connect_shell(self, peer):
        # peer is the source ip, host
        # json converts tuple to list
        peer = tuple(peer)

        child_pid, fd = pty.fork()
        if child_pid == 0:

            # Child process
            while log.hasHandlers():
                log.removeHandler(log.handlers[0])

            # trying to suppress log messages?!? Suspect it is this process
            # somehow sending data down the pipe to the remote SSL end causing
            # problems decoding ssl every once in a while
            try:
                subprocess.run("zsh")
            except:
                pass

        else:
            # Parent process

            # the peer may be the jumphost instead of actual browser,
            # we have no way of identifying if they are a jumphost so we
            # pass the RPCClient id of the originating request
            try:
                self.rpc_server.transport.attach_pty(child_pid, fd, peer)
                await self.rpc_server.transport.proxy_pty(peer)
            except Exception as e:
                print("In connect_shell")
                print(repr(e))

    async def disconnect_shell(self, peer):
        log.info(f"Disconnecting shell for peer: {peer[0]}")
        peer = tuple(peer)  # json convert to list
        self.rpc_server.transport.detach_pty(peer)

    def list_server_details(self):
        return {
            "working_dir": self.working_dir,
            "plugins": self.extensions.list_plugins(),
            "registrar_enabled": self.enable_registrar,
        }

    async def load_plugins(self, directory: str):
        p = Path(directory)

        if not p.is_absolute():
            p = self.working_dir / p

        log.info(f"loading plugins from directory {p}")

        # print(os.getcwd())
        sys.path.append(str(p))

        # or p.stat().st_size == 0:
        p.mkdir(parents=True, exist_ok=True)
        # if not p.exists():
        #     log.error("Plugin directory does not exist, skipping")
        #     return
        plugins = [
            f.rstrip(".py") for f in os.listdir(p) if os.path.isfile(os.path.join(p, f))
        ]

        log.debug(f"Plugins available: {plugins}")

        for f in plugins:
            importlib.invalidate_caches()
            # ToDo: wrap try / except
            try:
                plugin = importlib.import_module(f)
            except Exception as e:
                log.error(e)
            plugin = plugin.plugin
            if isinstance(plugin, FluxVaultExtensions):
                if plugin.required_packages:
                    try:
                        subprocess.run(
                            [sys.executable, "-m", "pip", "install"]
                            + plugin.required_packages,
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT,
                        )
                    except subprocess.CalledProcessError:
                        log.error("Error loading extensions packages, skipping")
                        return
                self.extensions.add_plugin(plugin)
                log.info(f"Plugin {plugin.plugin_name} loaded")
            else:
                log.error("Plugin load error... skipping")

    async def generate_csr(self):
        # ToDo: this needs to include a Fluxnode identifier
        altname = f"{self.component_name}.{self.app_name}.com"

        log.info(f"Generating CSR with altname {altname}")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.key = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        # public = key.public_key().public_bytes(
        #     Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        # )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, altname),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(altname),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return {"csr": csr.public_bytes(Encoding.PEM)}

    async def install_cert(self, cert_bytes: bytes):
        self.cert = cert_bytes
        cert = x509.load_pem_x509_certificate(cert_bytes)
        issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
        log.info(f"Installing cert from issuer {issuer} with Alt names {san}")

        # ToDo: this timing seems a bit off?
        await self.sub_agent.update_local_agent(enrolled=True)

    async def upgrade_connection(self):
        self.rpc_server.transport.upgrade_socket()

    async def install_ca_cert(self, cert_bytes: bytes):
        log.info("Installing CA cert")
        self.ca_cert = cert_bytes

    def extract_tar(self, file, target_dir):
        Path(target_dir).mkdir(parents=True, exist_ok=True)

        try:
            tar = tarfile.open(file)
            tar.extractall(target_dir)
            tar.close()
        # ToDo: Fix
        except Exception as e:
            log.error(repr(e))

    async def run_entrypoint(self, entrypoint: str):
        # ToDo: don't use shell
        proc = await asyncio.create_subprocess_shell(entrypoint)

        await proc.communicate()
