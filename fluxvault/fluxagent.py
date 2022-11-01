# standard library
import asyncio
import binascii
import time


# 3rd party
import aiofiles
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol


# this package - will move this to tinyrpc
from fluxvault.socketservertransport import SocketServerTransport
from fluxvault.dispatch import RPCDispatcher
from fluxvault.server import RPCServer


class FluxAgent:
    """Runs on Flux nodes - waits for connection from FluxKeeper"""

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        bind_port: int = 8888,
        dispatcher: RPCDispatcher = RPCDispatcher(),
        managed_files: list = [],
        working_dir: str = "/tmp",
        whitelisted_addresses: list = ["127.0.0.1"],
        authenticate_vault: bool = True,
    ):
        self.dispatcher = dispatcher
        self.working_dir = working_dir
        self.managed_files = managed_files
        self.loop = asyncio.get_event_loop()

        if authenticate_vault and not whitelisted_addresses:
            raise ValueError("whitelisted addresse(s) required if authenticating vault")

        dispatcher.add_method(self.get_all_files_crc)
        dispatcher.add_method(self.write_files)
        dispatcher.add_method(self.get_methods)

        transport = SocketServerTransport(
            bind_address,
            bind_port,
            whitelisted_addresses=whitelisted_addresses,
            authenticate_clients=authenticate_vault,
        )

        self.rpc_server = RPCServer(transport, JSONRPCProtocol(), self.dispatcher)

    def run(self):
        self.rpc_server.serve_forever()

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.dispatcher.method_map.items()}

    async def get_file_crc(self, fname):
        """Open the file and compute the crc, set crc=0 if not found"""
        # ToDo: catch file PermissionError
        try:
            # Todo: brittle
            async with aiofiles.open(self.working_dir + "/" + fname, mode="r") as file:
                content = await file.read()
                file.close()

                crc = binascii.crc32(content.encode("utf-8"))
        except FileNotFoundError:
            crc = 0

        return {"name": fname, "crc32": crc}

    async def get_all_files_crc(self) -> list:
        """Returns the crc32 for each file that is being managed"""
        print("Returning all vault files CRCs")
        tasks = []
        for file in self.managed_files:
            tasks.append(self.loop.create_task(self.get_file_crc(file)))
        results = await asyncio.gather(*tasks)
        return results

    async def write_file(self, fname, data):
        # ToDo: brittle af ("file location")
        # also ToDo: catch file PermissionError etc
        async with aiofiles.open(self.working_dir + "/" + fname, mode="w") as file:
            await file.write(data)

    async def write_files(self, files: dict):
        """Will write to disk any file provided, in the format {"name": <content>}"""
        # ToDo: this should be tasks
        for name, data in files.items():
            print(f"Writing file {name}")
            await self.write_file(name, data)
