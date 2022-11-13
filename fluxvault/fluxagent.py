# standard library
from __future__ import annotations

import asyncio
import binascii
import ipaddress
import logging
import os

# 3rd party
import aiofiles
from aiohttp import streamer, web
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.server import RPCServer
from aiotinyrpc.transports.socket import EncryptedSocketServerTransport

from fluxvault.extensions import FluxVaultExtensions

# this package
from fluxvault.helpers import get_app_and_component_name


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
        authenticate_vault: bool = True,
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

        self.test_workdir_access()

        if authenticate_vault and not whitelisted_addresses:
            raise ValueError("whitelisted address(es) required")

        self.component_name, self.app_name = get_app_and_component_name()

        extensions.add_method(self.get_all_files_crc)
        extensions.add_method(self.write_files)
        extensions.add_method(self.get_methods)
        # extensions.add_method(self.run_entrypoint)
        # extensions.add_method(self.extract_tar)

        transport = EncryptedSocketServerTransport(
            bind_address,
            bind_port,
            whitelisted_addresses=whitelisted_addresses,
            authenticate_clients=authenticate_vault,
        )
        self.rpc_server = RPCServer(transport, JSONRPCProtocol(), self.extensions)

        self.app.router.add_get("/file/{file_name}", self.download_file)

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
            self.loop.create_task(self.start_site(self.app, self.local_fileserver_port))
            self.log.info(
                f"Local file server running on port {self.local_fileserver_port}"
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
                f"Local file server running on port {self.local_fileserver_port}"
            )

        self.loop.create_task(self.rpc_server.serve_forever())

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
        if not ipaddress.ip_address(request.remote).is_private():
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

    async def write_files(self, files: dict):
        """Will write to disk any file provided, in the format {"name": <content>}"""
        # ToDo: this should be tasks
        for name, data in files.items():
            self.log.info(f"Writing file {name}")
            await self.write_file(name, data)
            self.log.info("Writing complete")
        self.ready_to_serve = True

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
