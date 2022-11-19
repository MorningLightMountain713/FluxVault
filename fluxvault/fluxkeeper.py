# Standard library
import asyncio
import binascii
import logging
import time
from typing import Callable

# 3rd party
import requests
from aiotinyrpc.client import RPCClient
from aiotinyrpc.exc import MethodNotFoundError
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.socket import EncryptedSocketClientTransport
from aiotinyrpc.auth import SignatureAuthProvider
from requests.exceptions import HTTPError

# this package
from fluxvault.extensions import FluxVaultExtensions


# ToDo: async
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
        sign_connections: bool = False,
        signing_key: str = "",
    ):
        self.app_name = app_name
        self.agent_ips = agent_ips if agent_ips else self.get_agent_ips()
        self.agents = {}
        self.extensions = extensions
        self.log = self.get_logger()
        self.loop = asyncio.get_event_loop()
        self.protocol = JSONRPCProtocol()
        self.vault_dir = vault_dir

        if not signing_key and sign_connections:
            raise ValueError("Signing key must be provided if signing connections")

        auth_provider = None
        if signing_key and sign_connections:
            auth_provider = SignatureAuthProvider(key=signing_key)

        for ip in self.agent_ips:
            transport = EncryptedSocketClientTransport(
                ip, comms_port, auth_provider=auth_provider
            )

            flux_agent = RPCClient(self.protocol, transport)
            self.agents.update({ip: flux_agent})

        self.extensions.add_method(self.get_all_agents_methods)
        self.extensions.add_method(self.poll_all_agents)

    def get_logger(self) -> logging.Logger:
        """Gets a logger"""
        return logging.getLogger("fluxvault")

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

    def compare_files(self, file: dict) -> dict:
        """Flux agent (node) is requesting a file"""

        # ToDo: Errors
        name = file["name"]
        crc = file["crc32"]

        remote_file_exists = False
        file_found_locally = True
        secret = ""

        if crc:  # remote file crc is 0 if it doesn't exist
            remote_file_exists = True

        try:
            # ToDo: file name is brittle
            # ToDo: catch file PermissionError
            with open(self.vault_dir + "/" + name, "rb") as file:
                file_data = file.read()
        except FileNotFoundError:
            file_found_locally = False
        else:  # file opened
            mycrc = binascii.crc32(file_data)
            if crc != mycrc:
                secret = file_data

        return {
            "file_found_locally": file_found_locally,
            "remote_file_exists": remote_file_exists,
            "secret": secret,
        }

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.extensions.method_map.items()}

    def get_all_agents_methods(self) -> dict:
        return self.loop.run_until_complete(self._get_agents_methods())

    async def get_agent_method(self, address, agent):
        await agent.transport.connect()

        if not agent.transport.connected:
            return {}

        agent_proxy = agent.get_proxy()
        methods = await agent_proxy.get_methods()
        await agent.transport.disconnect()
        return {address: methods}

    async def _get_agents_methods(self) -> dict:
        """Queries every agent and returns a list describing what methods can be run on
        each agent"""
        tasks = []
        for address, agent in self.agents.items():
            task = asyncio.create_task(self.get_agent_method(address, agent))
            tasks.append(task)

        all_methods = {}
        results = await asyncio.gather(*tasks)
        for result in results:
            all_methods.update(result)
        return all_methods

    async def poll_agent(self, address, agent):
        self.log.debug(f"Contacting Agent {address} to check if files required")

        await agent.transport.connect()
        if not agent.transport.connected:
            self.log.info("Transport not connected... skipping.")
            return  # transport will log warning

        agent_proxy = agent.get_proxy()

        files_to_write = {}
        files = await agent_proxy.get_all_files_crc()
        self.log.debug(f"Agent {address} remote file CRCs: {files}")

        if not files:
            self.log.warn(f"Agent {address} didn't request any files... skipping!")
            return

        for file in files:
            match_data = self.compare_files(file)
            self.log_file_match_details(file["name"], match_data)
            if match_data["secret"]:
                files_to_write.update({file["name"]: match_data["secret"]})

        if files_to_write:
            await agent_proxy.write_files(files=files_to_write)
        await agent.transport.disconnect()

    def poll_all_agents(self):
        self.loop.run_until_complete(self._poll_agents())

    async def _poll_agents(self):
        # ToDo: async
        """Checks if agents need any files delivered securely"""
        if not self.agent_ips:
            self.log.info("No agents found... nothing to do")

        polling_tasks = []
        for address, agent in self.agents.items():
            task = asyncio.create_task(self.poll_agent(address, agent))
            polling_tasks.append(task)
        await asyncio.gather(*polling_tasks)

    def log_file_match_details(self, file_name, match_data):
        if not match_data["file_found_locally"]:
            self.log.error(
                f"Agent requested file {self.vault_dir}/{file_name} not found locally... skipping!"
            )
        elif match_data["remote_file_exists"] and match_data["secret"]:
            self.log.info(
                f"Agent remote file {file_name} is different that local file... sending latest data"
            )
        elif match_data["remote_file_exists"]:
            self.log.info(
                f"Agent Requested file {file_name} is up to date... skipping!"
            )
        elif match_data["secret"]:
            self.log.info(f"Agent requested new file {file_name}... sending")

    # def run_agent_entrypoint(self):
    #     print(self.agents)
    #     agent = self.agents["127.0.0.1"]
    #     agent.one_way = True
    #     agent.run_entrypoint("/app/entrypoint.sh")

    def __getattr__(self, name: str) -> Callable:
        try:
            method = self.extensions.get_method(name)
        except MethodNotFoundError as e:
            raise AttributeError(f"Method does not exist: {e}")

        return method
