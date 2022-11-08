# standard library
import asyncio
import binascii
import time
import os

# 3rd party
import aiofiles
from aiotinyrpc.dispatch import RPCDispatcher
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.server import RPCServer

# this package - will move this to tinyrpc
# from fluxvault.socketservertransport import SocketServerTransport
# from fluxvault.dispatch import RPCDispatcher
# from fluxvault.server import RPCServer
from aiotinyrpc.transports.socket import EncryptedSocketServerTransport


class FluxAgent:
    """Runs on Flux nodes - waits for connection from FluxKeeper"""

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        bind_port: int = 8888,
        extensions: RPCDispatcher = RPCDispatcher(),
        managed_files: list = [],
        working_dir: str = "/tmp",
        whitelisted_addresses: list = ["127.0.0.1"],
        authenticate_vault: bool = True,
    ):
        self.extensions = extensions
        self.working_dir = working_dir
        self.managed_files = managed_files
        self.loop = asyncio.get_event_loop()

        if authenticate_vault and not whitelisted_addresses:
            raise ValueError("whitelisted addresse(s) required if authenticating vault")

        extensions.add_method(self.get_all_files_crc)
        extensions.add_method(self.write_files)
        extensions.add_method(self.get_methods)
        extensions.add_method(self.run_entrypoint)
        extensions.add_method(self.extract_tar)

        transport = EncryptedSocketServerTransport(
            bind_address,
            bind_port,
            whitelisted_addresses=whitelisted_addresses,
            authenticate_clients=authenticate_vault,
        )

        self.rpc_server = RPCServer(transport, JSONRPCProtocol(), self.extensions)

    def run(self):
        self.rpc_server.serve_forever()

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.extensions.method_map.items()}

    async def get_file_crc(self, fname):
        """Open the file and compute the crc, set crc=0 if not found"""
        # ToDo: catch file PermissionError
        try:
            # Todo: brittle
            async with aiofiles.open(self.working_dir + "/" + fname, mode="rb") as file:
                content = await file.read()
                file.close()

                crc = binascii.crc32(content)
        except FileNotFoundError:
            print("file not found")
            crc = 0
        except Exception as e:
            print(repr(e))

        return {"name": fname, "crc32": crc}

    async def get_all_files_crc(self) -> list:
        """Returns the crc32 for each file that is being managed"""
        print("Returning all vault files CRCs")
        tasks = []
        for file in self.managed_files:
            tasks.append(self.loop.create_task(self.get_file_crc(file)))
        results = await asyncio.gather(*tasks)
        return results

    def opener(self, path, flags):

        return os.open(path, flags, 0o777)

    async def write_file(self, fname, data):
        # ToDo: brittle af ("file location")
        # also ToDo: catch file PermissionError etc

        # os.umask(0)
        try:
            async with aiofiles.open(
                self.working_dir + "/" + fname,
                mode="wb",
                # self.working_dir + "/" + fname, mode="wb", opener=self.opener
            ) as file:
                await file.write(data)
        except Exception as e:
            print(repr(e))

    async def write_files(self, files: dict):
        """Will write to disk any file provided, in the format {"name": <content>}"""
        # ToDo: this should be tasks
        for name, data in files.items():
            print(f"Writing file {name}")
            await self.write_file(name, data)
            print("Writing complete")

    def extract_tar(self, file, target_dir):
        import tarfile
        from pathlib import Path

        Path(target_dir).mkdir(parents=True, exist_ok=True)

        try:
            tar = tarfile.open(file)
            tar.extractall(target_dir)
            tar.close()
        except Exception as e:
            print(repr(e))

    async def run_entrypoint(self, entrypoint):
        proc = await asyncio.create_subprocess_shell(entrypoint)

        await proc.communicate()
