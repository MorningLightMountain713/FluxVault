from __future__ import annotations

import asyncio
import binascii
import os
import ssl
import tempfile

import aiofiles
from aiohttp import ClientSession
from aiotinyrpc.auth import SignatureAuthProvider
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.server import RPCServer
from aiotinyrpc.transports.socket import EncryptedSocketServerTransport
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat)
from cryptography.x509.oid import ExtensionOID, NameOID

from fluxvault.extensions import FluxVaultExtensions
from fluxvault.helpers import get_app_and_component_name
from fluxvault.log import log
from fluxvault.registrar import (FluxAgentRegistrar, FluxPrimaryAgent,
                                 FluxSubAgent)


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
        managed_files: list = [],
        working_dir: str = "/tmp",
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
        self.managed_files = managed_files
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
                # print(resp.status)
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
                "Whitelisted addresses must be provided if verifying source ip address"
            )

        if self.subordinate and not self.primary_agent:
            raise ValueError("Primary agent must be provided if subordinate")

    def register_extensions(self):
        self.extensions.add_method(self.get_all_files_crc)
        self.extensions.add_method(self.write_files)
        self.extensions.add_method(self.get_methods)
        self.extensions.add_method(self.get_subagents)
        self.extensions.add_method(self.generate_csr)
        self.extensions.add_method(self.install_cert)
        self.extensions.add_method(self.install_ca_cert)
        self.extensions.add_method(self.upgrade_to_ssl)
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

        self.loop.create_task(self.rpc_server.serve_forever())

        try:
            self.loop.run_forever()
        finally:
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
        context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")

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
        self.rpc_server1 = RPCServer(transport, JSONRPCProtocol(), self.extensions)
        self.loop.create_task(self.rpc_server1.serve_forever())

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

    async def get_file_crc(self, fname: str) -> dict:
        """Open the file and compute the crc, set crc=0 if not found"""
        # ToDo: catch file PermissionError
        try:
            # Todo: brittle as
            async with aiofiles.open(self.working_dir + "/" + fname, mode="rb") as file:
                content = await file.read()
                file.close()

                crc = binascii.crc32(content)
        except FileNotFoundError:
            log.info(f"Local file {fname} not found")
            crc = 0
        # ToDo: Fix this
        except Exception as e:
            log.error(repr(e))
            crc = 0

        return {"name": fname, "crc32": crc}

    async def get_all_files_crc(self) -> list:
        """Returns the crc32 for each file that is being managed"""
        log.info("Returning all vault file hashes")
        tasks = []
        for file in self.managed_files:
            tasks.append(self.loop.create_task(self.get_file_crc(file)))
        results = await asyncio.gather(*tasks)
        return results

    async def write_file(self, fname: str, data: str | bytes, executable: bool = False):
        """Write a single file to disk"""
        # ToDo: brittle file path
        # ToDo: catch file PermissionError etc

        # os.umask(0) - set this is for everyone but doesn't really matter here

        if isinstance(data, bytes):
            mode = "wb"
        elif isinstance(data, str):
            mode = "w"
        else:
            raise ValueError("Data written must be either str or bytes")

        # this will make the file being written executable
        opener = self.opener if executable else None
        try:
            async with aiofiles.open(
                self.working_dir + "/" + fname, mode=mode, opener=opener
            ) as file:
                await file.write(data)
        # ToDo: whoa, tighten this up
        except Exception as e:
            log.error(repr(e))

    async def get_subagents(self):
        agents = {}
        if self.registrar:
            agents = {v.dns_name: v.as_dict() for v in self.registrar.sub_agents}
        return {"sub_agents": agents}

    async def write_files(self, files: dict):
        """Will write to disk any file provided, in the format {"name": <content>}"""
        # ToDo: this should be tasks
        for name, data in files.items():
            log.info(f"Writing file {name}")
            await self.write_file(name, data)
            log.info("Writing complete")

    async def generate_csr(self):
        if not self.component_name or not self.app_name:
            self.component_name = "component1"
            self.app_name = "testapp"
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

        await self.sub_agent.update_local_agent(enrolled=True)

    async def upgrade_connection(self):
        self.rpc_server.transport.upgrade_socket()

    async def install_ca_cert(self, cert_bytes: bytes):
        log.info("Installing CA cert")
        self.ca_cert = cert_bytes

    def extract_tar(self, file, target_dir):
        import tarfile
        from pathlib import Path

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
