# Standard library
import asyncio
import binascii
import time

# 3rd party
import requests
from requests.exceptions import HTTPError

from tinyrpc.client import RPCClient as _RPCClient
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.exc import RPCError

# this package - will move this to tinyrpc
from fluxvault.socketclienttransport import SocketClientTransport


class RPCClient(_RPCClient):
    async def _send_and_handle_reply(self, req, one_way):
        if self.transport.is_async:
            reply = await self.transport.send_message(req.serialize(), not one_way)

        else:
            # sends and expects for reply if connection is not one way
            reply = self.transport.send_message(req.serialize(), not one_way)

        if one_way:
            return

        # waits for reply
        response = self.protocol.parse_reply(reply)

        if hasattr(response, "error"):
            raise RPCError("Error calling remote procedure: %s" % response.error)

        return response

    def call(self, method, args=[], kwargs={}, one_way=False):
        """Calls the requested method and returns the result.

        If an error occured, an :py:class:`~tinyrpc.exc.RPCError` instance
        is raised.

        :param method: Name of the method to call.
        :param args: Arguments to pass to the method.
        :param kwargs: Keyword arguments to pass to the method.
        :param one_way: Whether or not a reply is desired.
        """
        loop = asyncio.get_event_loop()
        req = self.protocol.create_request(method, args, kwargs, one_way)

        rep = loop.run_until_complete(self._send_and_handle_reply(req, one_way))

        if one_way:
            return

        return rep.result


class FluxKeeper:
    def __init__(
        self, vault_dir: str, comms_port: int, app_name: str = "", agent_ips: list = []
    ):
        self.app_name = app_name
        self.agent_ips = agent_ips if agent_ips else self.get_agent_ips()
        self.agents = {}
        self.uncontactable_agents = []
        self.vault_dir = vault_dir
        self.loop = asyncio.get_event_loop()
        self.protocol = JSONRPCProtocol()

        for ip in self.agent_ips:
            transport = SocketClientTransport(ip, comms_port)

            if transport.connected():
                rpc_client = RPCClient(self.protocol, transport)
                flux_agent = rpc_client.get_proxy()
                self.agents.update({ip: flux_agent})
            else:
                print(f"Agent {ip}:{comms_port} uncontactable")
                self.uncontactable_agents.append((ip, comms_port))

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

        try:
            # ToDo: file name is brittle
            # ToDo: catch file PermissionError
            with open(self.vault_dir + "/" + name) as file:
                file_data = file.read()
        except FileNotFoundError:
            file_found = False
            crc_matched = False
        else:  # file opened
            mycrc = binascii.crc32(file_data.encode("utf-8"))
            if crc != mycrc:
                secret = file_data
                crc_matched = False

        return {"file_found": file_found, "crc_matched": crc_matched, "secret": secret}

    def get_all_agents_methods(self):
        for agent in self.agents.values():
            return agent.get_methods()

    def poll_all_agents(self):
        for agent in self.agents.values():
            files_to_write = {}
            files = agent.get_all_files_crc()
            print(f"Remote file CRCs: {files}")
            for file in files:
                match_data = self.compare_files(file)
                if match_data["secret"]:
                    print(f"File {file['name']} found, writing new content")
                    files_to_write.update({file["name"]: match_data["secret"]})
            if files_to_write:
                agent.write_files(files=files_to_write)
