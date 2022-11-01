"""This module is a single file that supports the loading of secrets into a Flux Node"""
import binascii
import json
from re import L
import sys
import time
from datetime import datetime
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from .old import state
from . import helpers

import asyncio

from time import sleep


class VaultException(Exception):
    pass


class VaultAuthenticationError(VaultException):
    pass


class VaultAgent:
    """Create a small server that runs on the Node waiting for Vault to connect"""

    def __init__(
        self,
        vault_name: str,
        vault_port: int,
        file_dir: str,
        user_files: list = [],
        is_flux_node: bool = True,
    ):
        self.max_message = 8192
        self.vault_name = vault_name
        self.vault_port = vault_port
        self.file_dir = file_dir
        self.user_files = user_files
        self.is_flux_node = is_flux_node

        self.sockets = {}

        self.state = state.DISCONNECTED
        self.key_data = {}
        self.send_queue = []
        self.encrypted = False

        self.response_actions = {
            state.DATA: self.write_vault_data_to_file,
        }

        self.actions = {"request_files": self.request_files}

    async def _start_server(self):
        self.server = await asyncio.start_server(
            self.socket_handler, "", self.vault_port
        )

        print("The VaultClient server is running on port " + str(self.vault_port))

        async with self.server:
            await self.server.serve_forever()

    def run(self):
        asyncio.run(self._start_server())

    async def outbound_message_handler(self, writer):
        try:
            msg = self.send_queue.pop(0)
            random = get_random_bytes(16).hex()
            msg["fill"] = random

        except IndexError:
            self.state = state.DONE
            msg = None

        if not msg:
            await asyncio.sleep(0.01)
            return

        # if encrypted
        if self.encrypted:
            print("About to be enc: ", msg)
            outbound_data = helpers.encrypt_aes_data(self.key_data["AESKEY"], msg)
        else:
            outbound_data = json.dumps(msg) + "\n"

        print("outbound data:")
        print(outbound_data)

        encoded = outbound_data.encode("utf-8")

        writer.write(encoded)
        await writer.drain()

    async def inbound_message_handler(self, reader):
        data = await reader.read(self.max_message)
        print("data: ", data)

        if data == b"":  # EOF
            self.state = state.DONE

        if self.state not in [state.READY, state.DONE]:
            # ToDo: this should handle failed too, (retry?)
            self.handle_encryption_messages(data)

        if self.state is state.READY and data:
            decrypted = helpers.decrypt_aes_data(self.key_data["AESKEY"], data)
            print("Decrypted: ", decrypted)
            if decrypted["State"] == "DATA":
                if self.write_vault_data_to_file(decrypted) and not self.send_queue:
                    self.send_queue.append({"State": "DONE"})

    async def socket_handler(self, reader, writer):
        peer_ip = writer.get_extra_info("peername")
        print(f"Connected: {peer_ip}")
        if not self.authenticated(peer_ip):
            print("Not authenticated")
            return

        # new connection from FluxVault
        if self.state is state.CONNECTED:
            print("Authenticated!")
            self.start_encryption()

        files_requested = False
        while self.state is not state.DONE:
            if self.encrypted and not files_requested:
                self.request_files()
                files_requested = True
            await self.outbound_message_handler(writer)
            await self.inbound_message_handler(reader)
        writer.close()
        await writer.wait_closed()
        self.state = state.DISCONNECTED
        self.encrypted = False
        print("DONE")

        # When we return the connection is closed

    def authenticated(self, peer_ip: str) -> bool:
        """Call when connection is established to verify correct source IP"""
        # Verify the connection came from our Vault IP Address
        if not self.vault_name:
            print("Vault Name not configured in FluxNode class or child class")
            return False
        hostname = self.vault_name
        # try:
        #     result = socket.gethostbyname(hostname)
        # except socket.gaierror:
        #     print(f"Vault name not vaild DNS: {hostname}")
        #     return False
        result = "127.0.0.1"
        if peer_ip[0] != result:
            # Delay invalid peer to defend against DOS attack
            time.sleep(15)
            print("Reject Connection, wrong IP:" + peer_ip[0] + " Expected " + result)
            return False
        self.state = state.CONNECTED
        self.user_request_count = 1
        return True

    def current_state(self) -> str:
        """Returns current state of the Node Key Data"""
        return self.state

    def generate_key_data(self):
        """"""
        self.key_data["RSAkey"] = RSA.generate(2048)
        self.key_data["Private"] = self.key_data["RSAkey"].export_key()
        self.key_data["Public"] = self.key_data["RSAkey"].publickey().export_key()

    def generate_public_key_message(self) -> str:
        """This is the only message sent unencrypted.
        This is Ok because the Public Key can be Public"""
        message = {
            "State": state.KEY_SENT,
            "PublicKey": self.key_data["Public"].decode("utf-8"),
        }

        # message = json.dumps(message) + "\n"
        return message

    def process_key_sent_response(self, reply: dict):
        # We send our Public key and expect an AES Key for our session, if not Get Out
        if reply["State"] != state.AES_KEY:
            print("fucked")
            print(reply["State"])
            self.state = state.FAILED
            return

        print("processing key sent response")
        # Decrypt with our RSA Private Key
        self.key_data["AESKEY"] = helpers.decrypt_data(self.key_data["Private"], reply)
        self.state = state.START_AES
        # Send a test encryption request, always include random data
        random = get_random_bytes(16).hex()
        msg = {"State": state.START_AES, "Text": "Test", "fill": random}
        # Encrypt with AES Key and send request
        self.encrypted = True
        self.send_queue.append(msg)

    def process_start_aes_response(self, message):
        # Do we both have the same AES Key?
        response = helpers.decrypt_aes_data(
            self.key_data["AESKEY"], json.dumps(message)
        )
        print("aes response: ", response)
        if response["State"] == state.START_AES and response["Text"] == "Passed":
            self.state = state.READY  # We are good to go!
            # self.send_queue.append({"State": state.PASSED})
        else:
            self.state = state.FAILED  # Tollerate no errors

    def start_encryption(self):
        print("Starting encryption")
        self.generate_key_data()
        self.state = state.KEY_SENT
        start_encryption_message = self.generate_public_key_message()
        print("sending public key message")
        self.send_queue.append(start_encryption_message)

    def handle_encryption_messages(self, msg):
        """Dispatch incoming message"""
        try:
            message = json.loads(msg.decode("utf-8"))
        except ValueError:
            self.state = state.FAILED
            print("Error decoding json")
            return

        if self.state is state.KEY_SENT:
            # this sends a START_AES message
            self.process_key_sent_response(message)
            return

        if self.state is state.START_AES:
            # this sets state to passed
            self.process_start_aes_response(message)

    def process_payload_message(self, response):
        """
        Handle Agent replies, the response "State" field tells us what action is needed.
        Each State should be unique because the state value (string) is used to
        define the function called in the self.response_actions dict

        If the none of the agent functions do not handle the request we abort the connection,
        otherwise the agent calls the user_request function to with a step number 1..n
        The default user_request function will request all files define in the bootfiles array
        The MyFluxNode class (example in vault_node.py) can redefine teh user_request function
        """
        print("process payload")
        if response["State"] == state.PASSED:
            self.request_files()
        else:
            pass  # what?

    # this is called by the FluxVault via a response message
    def write_vault_data_to_file(self, request) -> bool:
        """Node side processing of vault replies for all predefined actions"""
        print(request)
        if request["Status"] == "Success":
            with open(self.file_dir + request["FILE"], "w", encoding="utf-8") as file:
                file.write(request["Body"])
                file.close()
                print(request["FILE"], " received!")
                return True
        if request["Status"] == "Match":
            print(request["FILE"], " Match!")
            return True
        if request["Status"] == "FileNotFound":
            print(request["FILE"], " was not found?")
            return True
        return False

    def request_file(self, fname) -> None:
        """Open the file and compute the crc, set crc=0 if not found"""
        try:
            with open(self.file_dir + fname, encoding="utf-8") as file:
                content = file.read()
                file.close()
            crc = binascii.crc32(content.encode("utf-8"))
            # File exists
        except FileNotFoundError:
            crc = 0
        self.send_queue.append({"State": state.REQUEST, "FILE": fname, "crc32": crc})

    def request_files(self):
        """Defined by User class, if needed"""
        for file in self.user_files:
            self.request_file(file)


# Routines for fluxVault class
def open_connection(port, appip):
    """Open socket to Node"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        return "Failed to create socket"

    try:
        remote_ip = socket.gethostbyname(appip)
    except socket.gaierror:
        return "Hostname could not be resolved"

    # Set short timeout
    sock.settimeout(30)

    # Connect to remote server
    try:
        error = None
        #  print('# Connecting to server, ' + appip + ' (' + remote_ip + ')')
        sock.connect((remote_ip, port))
    except ConnectionRefusedError:
        error = appip + " connection refused"
        sock.close()
        sock = None
    except TimeoutError:
        error = appip + " Connect TimeoutError"
        sock.close()
        sock = None
    except socket.error:
        error = appip + " No route to host"
        sock.close()
        sock = None

    if sock is None:
        return error

    sock.settimeout(None)
    # Set longer timeout
    sock.settimeout(60)
    return sock


class VaultKeeper:
    """Class for the Secure Vault Agent, runs on secured trusted server or PC behind firewall"""

    # pylint: disable=too-many-instance-attributes
    def __init__(self) -> None:
        # super(fluxVault, self).__init__()
        self.request = {}
        self.file_dir = ""
        self.vault_port = 0
        self.result = "Initialized"
        self.agent_requests = {
            state.DONE: self.node_done,
            state.REQUEST: self.node_request,
        }
        self.log = []
        self.verbose = False
        self.matched = False

    def add_log(self, msg):
        """Add logging of notable events"""
        cur_time = datetime.now()
        now = cur_time.strftime("%b-%d-%Y %H:%M:%S ")
        self.log.append(now + msg)
        if self.verbose:
            print(now + msg)

    def vault_agent(self):
        """Invokes requested agent action defined by FluxVault or user defined class"""
        node_func = self.agent_requests.get(self.request["State"], None)
        if node_func is None:
            return None
        jdata = node_func()
        return jdata

    def node_done(self):
        """Node is done with this session"""
        # The Node is done with us, Get Out!
        return self.request

    def node_request(self):
        """Node is requesting a file"""
        fname = self.request["FILE"]
        crc = int(self.request["crc32"])
        self.request["State"] = "DATA"
        # Open the file, read contents and compute the crc
        # if the CRC matches no need to resent
        # if it does not exist locally report the error
        try:
            with open(self.file_dir + fname, encoding="utf-8") as file:
                secret = file.read()
                file.close()
            mycrc = binascii.crc32(secret.encode("utf-8"))
            if crc == mycrc:
                if self.verbose:
                    print("File " + fname + " Matched!")
                self.request["Status"] = "Match"
                self.request["Body"] = ""
            else:
                self.add_log("File " + fname + " sent!")
                self.request["Body"] = secret
                self.request["Status"] = "Success"
                self.matched = False
        except FileNotFoundError:
            self.add_log("File Not Found: " + self.file_dir + fname)
            self.request["Body"] = ""
            self.request["Status"] = "FileNotFound"
            self.matched = False
        return self.request

    def do_encrypted(self, sock, aeskey, jdata):
        """
        This function will send the reply and process any file requests it receives
        The rest of the session will use the aeskey to protect the session
        send_files(sock, jdata, aeskey, file_dir)"""
        while True:
            print("To be encrypted outbound: ", jdata)
            # Encrypt the latest reply
            data = helpers.encrypt_aes_data(aeskey, jdata)
            reply = helpers.send_receive(sock, data)
            if reply is None:
                self.result = "Receive Time out"
                self.add_log(self.result)
                break
            # Reply sent and next command received, decrypt and process
            self.request = helpers.decrypt_aes_data(aeskey, reply)
            print(self.request)
            # call vault_agent functions
            jdata = self.vault_agent()
            if jdata is None:
                break
            if jdata["State"] == state.DONE:
                self.result = "Completed"
                break

    def node_vault_ip(self, appip):
        """
        This is where all the Vault work is done.
        Use the port and appip to connect to a Node and give it files it asks for
        """

        if self.vault_port == 0:
            self.result = "vault_port Not set!"
            self.add_log(self.result)
            return
        # Open socket to the node
        sock = open_connection(self.vault_port, appip)
        if isinstance(sock, str):
            self.result = sock
            if self.verbose:
                print("Could not connect to Node")
            self.add_log(self.result)
            return

        self.result = "Connected"
        # Use While loop to allow graceful escape on error
        while True:
            print(self.result)
            # Node will generate a RSA Public/Private key pair and send us the Public Key
            # this message will be signed by the Flux Node private key so we can authenticate
            # that we are connected to node we expect (no man in the middle)

            public_key = helpers.receive_public_key(sock)
            if public_key is None:
                self.result = "No Public Key Received"
                self.add_log(self.result)
                break

            # Generate and send AES Key encrypted with PublicKey just received
            # These are only used for this session and are memory resident
            aeskey = get_random_bytes(16).hex().encode("utf-8")
            # Create a cypher message (json) and the data is simply the aeskey we will use
            jdata = helpers.encrypt_data(public_key, aeskey)
            # The State reflects what format the cypher message is
            jdata["State"] = state.AES_KEY
            data = json.dumps(jdata)

            # Send the message and wait for the reply to verify the key exchange was successful
            reply = helpers.send_receive(sock, data)
            if reply is None:
                self.result = "Receive Time out"
                self.add_log(self.result)
                break
            # AES Encryption should be started now, decrypt the message and validate the reply
            jdata = helpers.decrypt_aes_data(aeskey, reply)
            if jdata["State"] != state.START_AES:
                self.result = "StartAES not found"
                self.add_log(self.result)
                break
            if jdata["Text"] != "Test":
                self.result = "StartAES Failed"
                self.add_log(self.result)
                break
            # Form and format looks good, prepare reply and indicate we Passed
            jdata["Text"] = "Passed"

            self.result = "Connected and Encrypted"
            self.do_encrypted(sock, aeskey, jdata)
            break
        sock.close()
        return


if __name__ == "__main__":
    client = VaultClient("blah", 33333, "/tmp/", ["wango.txt", "quotes.txt"])
    client.run()
