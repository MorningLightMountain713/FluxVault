# standard library
from __future__ import annotations

import asyncio
import binascii
import ipaddress
import logging
import os

import ssl

# 3rd party
import aiofiles
from aiohttp import streamer, web, ClientSession, ClientTimeout, ClientConnectorError

from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.server import RPCServer
from aiotinyrpc.transports.socket import EncryptedSocketServerTransport
from aiotinyrpc.auth import SignatureAuthProvider

from fluxvault.extensions import FluxVaultExtensions

# this package
from fluxvault.helpers import get_app_and_component_name, _get_own_ip


### figure out all this
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import (
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


class FluxAgentException(Exception):
    pass


class FluxAgent:
    """Runs on Flux nodes - waits for connection from FluxKeeper"""

    @streamer
    async def file_sender(writer, file_path=None):
        """
        This function will read large file chunk by chunk and send it through HTTP
        without reading them into memory
        """
        with open(file_path, "rb") as f:
            chunk = f.read(2**16)
            while chunk:
                await writer.write(chunk)
                chunk = f.read(2**16)

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        bind_port: int = 8888,
        enable_local_fileserver: bool = False,
        local_fileserver_port: int = 2080,
        extensions: FluxVaultExtensions = FluxVaultExtensions(),
        managed_files: list = [],
        working_dir: str = "/tmp",
        whitelisted_addresses: list = ["127.0.0.1"],
        verify_source_address: bool = False,
        signed_vault_connections: bool = False,
        zelid: str = "",
        subordinate: bool = False,
        primary_agent_name: str = "fluxagent",
        superior_address: str = "",
        superior_port: str = "",
    ):
        self.app = web.Application()
        self.enable_local_fileserver = enable_local_fileserver
        self.extensions = extensions
        self.log = self.get_logger()
        self.local_fileserver_port = local_fileserver_port
        self.loop = asyncio.get_event_loop()
        self.managed_files = managed_files
        self.ready_to_serve = False
        self.runners = []
        self.working_dir = working_dir
        self.subordinate = subordinate
        self.primary_agent_name = primary_agent_name
        self.superior_address = superior_address
        self.superior_port = superior_port
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.whitelisted_addresses = whitelisted_addresses
        self.verify_source_address = verify_source_address

        self.sub_agents = {}

        self.test_workdir_access()

        if verify_source_address and not whitelisted_addresses:
            raise ValueError(
                "Whitelisted addresses must be provided if verifying source ip address"
            )

        self.component_name, self.app_name = get_app_and_component_name()

        extensions.add_method(self.get_all_files_crc)
        extensions.add_method(self.write_files)
        extensions.add_method(self.get_methods)
        extensions.add_method(self.get_subagents)
        extensions.add_method(self.generate_csr)
        extensions.add_method(self.install_cert)
        extensions.add_method(self.install_ca_cert)
        extensions.add_method(self.upgrade_to_ssl)
        # extensions.add_method(self.run_entrypoint)
        # extensions.add_method(self.extract_tar)

        self.auth_provider = None
        if signed_vault_connections:
            # this is solely for testing without an app
            if zelid:
                address = zelid
            else:
                address = self.loop.run_until_complete(self.get_app_owner_zelid())
            self.log.info(f"App zelid is: {address}")
            self.auth_provider = SignatureAuthProvider(address=address)

        transport = EncryptedSocketServerTransport(
            bind_address,
            bind_port,
            whitelisted_addresses=whitelisted_addresses,
            verify_source_address=verify_source_address,
            auth_provider=self.auth_provider,
        )
        self.rpc_server = RPCServer(transport, JSONRPCProtocol(), self.extensions)

        # self.app.router.add_get("/file/{file_name}", self.download_file)

        # if self.component_name.lower() != "fluxagent":
        if self.subordinate:
            self.loop.run_until_complete(self.register_with_local_agent())
        else:
            self.app.router.add_post("/register", self.handle_register)
            self.app.router.add_post("/update", self.handle_update)

    async def handle_update(self, request: web.Request) -> web.Response:
        data = await request.json()
        client_name = data.get("name")
        client_role = data.get("role")
        client_enrolled = data.get("enrolled")
        self.sub_agents.update(
            {client_name: {"role": client_role, "enrolled": client_enrolled}}
        )
        self.log.info(f"Sub agent updated {client_name}, enrolled: {client_enrolled}")
        return web.Response(
            status=202,
        )

    async def handle_register(self, request: web.Request) -> web.Response:
        data = await request.json()
        client_name = data.get("name")
        client_role = data.get("role")
        self.sub_agents.update({client_name: {"role": client_role, "enrolled": False}})
        self.log.info(f"New sub agent registered {client_name} with role {client_role}")
        return web.Response(
            status=202,
        )

    async def register_with_local_agent(self):
        url = f"http://flux{self.primary_agent_name}_{self.app_name}:{self.local_fileserver_port}/register"
        name = f"flux{self.component_name}_{self.app_name}"

        if self.superior_address and self.superior_port:
            # this means were a subordinate and not on a flux node, basically testing
            url = f"http://{self.superior_address}:{self.superior_port}/register"
            name = self.bind_address
        registered = False
        while not registered:
            try:
                data = {
                    "name": name,
                    "role": "mongo",
                }
                async with ClientSession(timeout=ClientTimeout(3)) as session:
                    async with session.post(url, json=data) as resp:
                        if resp.status == 202:
                            registered = True
            except (asyncio.exceptions.TimeoutError, ClientConnectorError):
                self.log.error(
                    f"Unable to connect to local fluxagent @ {url}... trying again in 5"
                )
                await asyncio.sleep(5)
        self.log.info("Successfully registered with primary agent")

    async def update_local_agent(self, data: dict):
        url = f"http://flux{self.primary_agent_name}_{self.app_name}:{self.local_fileserver_port}/update"

        if self.superior_address and self.superior_port:
            # this means were a subordinate and not on a flux node, basically testing
            url = f"http://{self.superior_address}:{self.superior_port}/update"

        try:
            async with ClientSession(timeout=ClientTimeout(3)) as session:
                async with session.post(url, json=data) as resp:
                    pass
        except (asyncio.exceptions.TimeoutError, ClientConnectorError):
            self.log.error("Unable to connect to local fluxagent...")
        self.log.info("Successfully updated with primary agent")

    async def get_app_owner_zelid(self) -> str:
        async with ClientSession() as session:
            async with session.get(
                f"https://api.runonflux.io/apps/appowner?appname={self.app_name}"
            ) as resp:
                # print(resp.status)
                data = await resp.json()
                zelid = data.get("data", "")
        return zelid

    def get_logger(self) -> logging.Logger:
        """Gets a logger"""
        return logging.getLogger("fluxvault")

    def test_workdir_access(self):
        """Minimal test to ensure we can at least read the working dir"""
        try:
            os.listdir(self.working_dir)
        except Exception as e:
            raise FluxAgentException(f"Error accessing working directory: {e}")

    def run(self):
        if self.enable_local_fileserver:
            self.loop.create_task(
                self.start_site(self.app, port=self.local_fileserver_port)
            )
            self.log.info(
                f"Sub agent http server running on port {self.local_fileserver_port}"
            )

        self.loop.create_task(self.rpc_server.serve_forever())

        try:
            self.loop.run_forever()
        finally:
            for runner in self.runners:
                self.loop.run_until_complete(runner.cleanup())

    async def run_async(self):
        if self.enable_local_fileserver:
            self.loop.create_task(self.start_site(self.app, self.local_fileserver_port))
            self.log.info(
                f"Sub agent http server running on port {self.local_fileserver_port}"
            )

        self.loop.create_task(self.rpc_server.serve_forever())

    async def upgrade_to_ssl(self):
        import tempfile

        cert = tempfile.NamedTemporaryFile()
        key = tempfile.NamedTemporaryFile()
        ca_cert = tempfile.NamedTemporaryFile()
        with open(cert.name, "wb") as f:
            f.write(self.cert)
        with open(key.name, "wb") as f:
            f.write(self.key)
        with open(ca_cert.name, "wb") as f:
            f.write(self.ca_cert)

        self.log.info("Upgrading connection to ssl")
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
        self.log.info("current server stopped")
        self.rpc_server1 = RPCServer(transport, JSONRPCProtocol(), self.extensions)
        self.loop.create_task(self.rpc_server1.serve_forever())

    def cleanup(self):
        # ToDo: look at cleanup for rpc server too
        for runner in self.runners:
            self.loop.run_until_complete(runner.cleanup())

    async def start_site(
        self, app: web.Application, address: str = "0.0.0.0", port: int = 2080
    ):
        runner = web.AppRunner(app)
        self.runners.append(runner)
        await runner.setup()
        site = web.TCPSite(runner, address, port)
        await site.start()

    async def download_file(self, request: web.Request) -> web.Response:
        # ToDo: Base downloads on component name
        # ToDo: Only auth once, not per request

        # We only accept connections from local network. (Protect against punter
        # exposing the fileserver port on the internet)
        if not ipaddress.ip_address(request.remote).is_private:
            return web.Response(
                body="Unauthorized",
                status=403,
            )
        remote_component, remote_app = get_app_and_component_name(request.remote)
        if remote_app != self.app_name:
            return web.Response(
                body="Unauthorized",
                status=403,
            )
        if not self.ready_to_serve:
            return web.Response(
                body="Service unavailable - waiting for Keeper to connect",
                status=503,
            )

        file_name = request.match_info["file_name"]
        headers = {
            "Content-disposition": "attachment; filename={file_name}".format(
                file_name=file_name
            )
        }

        file_path = os.path.join(self.working_dir, file_name)

        if not os.path.exists(file_path):
            return web.Response(
                body="File <{file_name}> does not exist".format(file_name=file_name),
                status=404,
            )

        return web.Response(
            body=FluxAgent.file_sender(file_path=file_path), headers=headers
        )

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
            self.log.info(f"Local file {fname} not found")
            crc = 0
        # ToDo: Fix this
        except Exception as e:
            self.log.error(repr(e))
            crc = 0

        return {"name": fname, "crc32": crc}

    async def get_all_files_crc(self) -> list:
        """Returns the crc32 for each file that is being managed"""
        self.log.info("Returning all vault file hashes")
        tasks = []
        for file in self.managed_files:
            tasks.append(self.loop.create_task(self.get_file_crc(file)))
        results = await asyncio.gather(*tasks)
        return results

    def opener(self, path, flags):

        return os.open(path, flags, 0o777)

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
            self.log.error(repr(e))

    # async def proxy_request(self, host, port):
    #     self.rpc_server.transport.forward_request("host", "port")
    #     return True

    async def get_subagents(self):
        return {"sub_agents": self.sub_agents}

    async def write_files(self, files: dict):
        """Will write to disk any file provided, in the format {"name": <content>}"""
        # ToDo: this should be tasks
        for name, data in files.items():
            self.log.info(f"Writing file {name}")
            await self.write_file(name, data)
            self.log.info("Writing complete")
        self.ready_to_serve = True

    async def generate_csr(self):
        if not self.component_name or not self.app_name:
            self.component_name = "component1"
            self.app_name = "testapp"
        altname = f"{self.component_name}.3-3-3-3.{self.app_name}.com"

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # ToDO: store this? or just make a new one
        self.key = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        # print(
        # key.public_key().public_bytes(
        #     Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        # )
        # )

        # with open("component1.key", "wb+") as f:
        #     f.write(
        #         key.public_key().public_bytes(
        #             Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        #         )
        #     )

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
        # cert = x509.load_pem_x509_certificate(cert_bytes)
        self.cert = cert_bytes

        # with open("component1.pem", "wb+") as f:
        #     f.write(cert_bytes)

        # print(self.cert.issuer)
        # print(self.cert.subject)
        data = {
            "name": f"flux{self.component_name}_{self.app_name}",
            "role": "mongo",
            "enrolled": True,
        }
        await self.update_local_agent(data)

    async def upgrade_connection(self):
        self.rpc_server.transport.upgrade_socket()

    async def install_ca_cert(self, cert_bytes: bytes):
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
            self.log.error(repr(e))

    async def run_entrypoint(self, entrypoint: str):
        # ToDo: don't use shell
        proc = await asyncio.create_subprocess_shell(entrypoint)

        await proc.communicate()
