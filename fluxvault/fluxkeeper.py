# Standard library
import asyncio
import binascii
import time
from typing import Callable

# 3rd party
import requests
from aiotinyrpc.client import RPCClient
from aiotinyrpc.dispatch import RPCDispatcher
from aiotinyrpc.exc import MethodNotFoundError
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.socket import EncryptedSocketClientTransport
from requests.exceptions import HTTPError


# ToDo: async
class FluxKeeper:
    """Oracle like object than runs in your protected environment. Provides runtime
    data to your vulnerable services in a secure manner

    The end goal is to be able to secure an application's private data where visibility
    of that data is restricted to the application owner

    This class, in combination with FluxVault - is one of the first steps in fulfilling
    the above goal"""

    def __init__(
        self,
        vault_dir: str,
        comms_port: int,
        app_name: str = "",
        agent_ips: list = [],
        extensions: RPCDispatcher = RPCDispatcher(),
    ):
        self.app_name = app_name
        self.agent_ips = agent_ips if agent_ips else self.get_agent_ips()
        self.agents = {}
        self.extensions = extensions
        self.uncontactable_agents = []
        self.vault_dir = vault_dir
        self.loop = asyncio.get_event_loop()
        self.protocol = JSONRPCProtocol()

        for ip in self.agent_ips:
            transport = EncryptedSocketClientTransport(ip, comms_port)

            if transport.connected():
                rpc_client = RPCClient(self.protocol, transport)
                flux_agent = rpc_client.get_proxy()
                self.agents.update({ip: flux_agent})
            else:
                print(f"Agent {ip}:{comms_port} uncontactable")
                self.uncontactable_agents.append((ip, comms_port))

        self.extensions.add_method(self.get_all_agents_methods)
        self.extensions.add_method(self.poll_all_agents)

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
        """Node is requesting a file"""

        # ToDo: Errors
        name = file["name"]
        crc = file["crc32"]

        crc_matched = True
        file_found = True
        secret = ""

        print("comparing files")
        try:
            # ToDo: file name is brittle
            # ToDo: catch file PermissionError
            with open(self.vault_dir + "/" + name, "rb") as file:
                print("file opened")
                file_data = file.read()
        except FileNotFoundError:
            print("file not found!!")
            file_found = False
            crc_matched = False
        else:  # file opened
            mycrc = binascii.crc32(file_data)
            if crc != mycrc:
                secret = file_data
                crc_matched = False

        return {"file_found": file_found, "crc_matched": crc_matched, "secret": secret}

    def get_methods(self):
        """Returns methods available for the keeper to call"""
        return {k: v.__doc__ for k, v in self.extensions.method_map.items()}

    def get_all_agents_methods(self):
        """Queries every agent and returns a list describing what methods can be run on
        each agent"""
        # Todo test multiple agents
        for agent in self.agents.values():
            return agent.get_methods()

    def poll_all_agents(self):
        for agent in self.agents.values():
            files_to_write = {}
            files = agent.get_all_files_crc()
            print(f"Remote file CRCs: {files}")
            for file in files:
                match_data = self.compare_files(file)
                print(match_data)
                if match_data["secret"]:
                    print(f"File {file['name']} found, writing new content")
                    files_to_write.update({file["name"]: match_data["secret"]})
            if files_to_write:
                agent.write_files(files=files_to_write)

    def run_agent_entrypoint(self):
        print(self.agents)
        agent = self.agents["127.0.0.1"]
        agent.one_way = True
        agent.run_entrypoint("/app/entrypoint.sh")

    def __getattr__(self, name: str) -> Callable:
        try:
            method = self.extensions.get_method(name)
        except MethodNotFoundError as e:
            raise AttributeError(f"Method does not exist: {e}")

        return method
