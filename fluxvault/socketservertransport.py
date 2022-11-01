from __future__ import annotations  # 3.10 style

import json
import asyncio

from tinyrpc.transports import ServerTransport

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


class SocketServerTransport(ServerTransport):
    def __init__(
        self,
        address: str,
        port: int,
        whitelisted_addresses: list = [],
        authenticate_clients: bool = False,
    ):
        self._address = address
        self._port = port
        self.is_async = True
        self.sockets = {}
        self.messages = []
        self.seperator = b"<?!!?>"
        # ToDo: validate addresses
        self.whitelisted_addresses = whitelisted_addresses
        self.authenticate_clients = authenticate_clients

    async def encrypt_socket(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.generate_key_data(peer)

        # ToDo: does receive_on_socket need to return peer?
        await self.send(writer, self.sockets[peer]["key_data"]["Public"])
        _, encrypted_aes_key = await self.receive_on_socket(peer, reader)

        # ToDo: try / except
        aeskey = self.decrypt_data(
            self.sockets[peer]["key_data"]["Private"], json.loads(encrypted_aes_key)
        )
        self.sockets[peer]["key_data"]["AESKEY"] = aeskey

        # Send a test encryption request, always include random data
        random = get_random_bytes(16).hex()
        test_msg = {"text": "TestEncryptionMessage", "fill": random}
        enc_msg = json.dumps(test_msg).encode()
        # ToDo: this function should take dict, str or bytes
        encrypted_test_msg = self.encrypt_aes_data(aeskey, enc_msg)
        await self.send(writer, encrypted_test_msg)
        _, res = await self.receive_on_socket(peer, reader)

        response = self.decrypt_aes_data(aeskey, res)

        if (
            response.get("text") == "TestEncryptionMessageResponse"
            and response.get("fill") == random[::-1]
        ):
            self.sockets[peer]["encrypted"] = True
        print("Encryption state:", self.sockets[peer]["encrypted"])

    def decrypt_data(self, keypem: str, cipher: dict) -> str:
        """Used by Node to decrypt and return the AES Session key using the RSA Key"""
        private_key = RSA.import_key(keypem)
        enc_session_key = bytes.fromhex(cipher["enc_session_key"])
        nonce = bytes.fromhex(cipher["nonce"])
        tag = bytes.fromhex(cipher["tag"])
        ciphertext = bytes.fromhex(cipher["cipher"])

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data

    def generate_key_data(self, peer):
        rsa = RSA.generate(2048)
        rsa_private = rsa.export_key()
        rsa_public = rsa.publickey().export_key()
        self.sockets[peer]["key_data"] = {
            "RSAkey": rsa,
            "Private": rsa_private,
            "Public": rsa_public,
        }

    async def authenticated(self, peer_ip) -> bool:
        """Called when connection is established to verify correct source IP"""
        if peer_ip not in self.whitelisted_addresses:
            # Delaying here doesn't really stop against a DoS attack so have lowered
            # this to 3 seconds. In fact, it makes it even easier to DoS as you have an
            # open socket consuming resources / port
            await asyncio.sleep(3)
            print(
                f"Reject Connection, wrong IP: {peer_ip} Expected {self.whitelisted_addresses}"
            )
            return False
        return True

    def decrypt_data(self, keypem: str, cipher: dict) -> str:
        """Used by Node to decrypt and return the AES Session key using the RSA Key"""
        private_key = RSA.import_key(keypem)
        enc_session_key = bytes.fromhex(cipher["enc_session_key"])
        nonce = bytes.fromhex(cipher["nonce"])
        tag = bytes.fromhex(cipher["tag"])
        ciphertext = bytes.fromhex(cipher["cipher"])

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data

    # ToDo: Fix up error
    def decrypt_aes_data(self, key, data: bytes) -> dict:
        """
        Accept out cipher text object
        Decrypt data with AES key
        """
        try:
            jdata = json.loads(data)
            nonce = bytes.fromhex(jdata["nonce"])
            tag = bytes.fromhex(jdata["tag"])
            ciphertext = bytes.fromhex(jdata["ciphertext"])

            # let's assume that the key is somehow available again
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            msg = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise
        return json.loads(msg)

    def encrypt_aes_data(self, key, data: bytes) -> bytes:
        """
        Take a json object, dump it in plain text
        Encrypt data with AES key
        Create a json object with the cipher text and digest
        Then return that object in plain text to send to our peer
        """
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        jdata = {
            "nonce": cipher.nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex(),
        }
        return json.dumps(jdata).encode("utf-8")

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        print("Peer connected:", peer)

        if self.authenticate_clients and not await self.authenticated(peer[0]):
            writer.close()
            return

        self.sockets[peer] = {
            "encrypted": False,
            "reader": reader,
            "writer": writer,
            "key_data": {},
        }

        await self.encrypt_socket(reader, writer)

        running = True

        while running:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            message = await asyncio.wait_for(task, None)

            if message:
                print("Message received (decrypted):", message)
                self.messages.append(message)
            else:  # Socket closed
                running = False

    async def start_server(self):
        # ToDo: pass in variables
        self.server = await asyncio.start_server(
            self.handle_client, self._address, self._port, start_serving=True
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        print(f"Serving on {addrs}")

    async def receive_on_socket(self, peer, reader) -> tuple | None:
        if reader.at_eof():
            self.sockets[peer]["writer"].close()
            del self.sockets[peer]
            print("AT EOF")
            return None
        try:
            data = await reader.readuntil(separator=self.seperator)
        except asyncio.exceptions.IncompleteReadError:
            return None

        message = data.rstrip(self.seperator)
        message = message.decode()

        if self.sockets[peer]["encrypted"]:
            message = self.decrypt_aes_data(
                self.sockets[peer]["key_data"]["AESKEY"], message
            )
            message = json.dumps(message).encode()

        return (peer, message)

    async def receive_message(self) -> tuple:
        while not self.messages:
            # ToDo: Set this via param, debug 0.5, prod 0.05
            await asyncio.sleep(0.05)

        addr, message = self.messages.pop(0)
        return addr, message

    async def send(self, writer, reply):
        writer.write(reply + self.seperator)
        await writer.drain()

    async def send_reply(self, context: tuple, reply: bytes):
        if self.sockets[context]["encrypted"]:
            reply = self.encrypt_aes_data(
                self.sockets[context]["key_data"]["AESKEY"], reply
            )

        writer = self.sockets[context]["writer"]
        await self.send(writer, reply)
