import asyncio
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

from tinyrpc.transports import ClientTransport


class SocketClientTransport(ClientTransport):
    def __init__(self, address, port, **parameters):
        self._address = address
        self._port = port
        self._connected = False
        self.is_async = True
        self.encrypted = False
        self.seperator = b"<?!!?>"
        self.loop = asyncio.get_event_loop()
        self.reader, self.writer = None, None

        self.loop.run_until_complete(self.get_connection())

        if not self.reader and not self.writer:
            return

        self._connected = True

        self.loop.run_until_complete(self.setup_encryption())

    def serialize(self, msg):
        return json.dumps(msg).encode()

    def encrypt_data(self, keypem: str, data: str) -> dict:
        """Used by the Vault to create and send a AES session key protected by RSA"""
        key = RSA.import_key(keypem)
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        msg = {
            "enc_session_key": enc_session_key.hex(),
            "nonce": cipher_aes.nonce.hex(),
            "tag": tag.hex(),
            "cipher": ciphertext.hex(),
        }
        return msg

    async def setup_encryption(self):
        # ToDo: maybe get the other end to return a useful message here if authentication failed
        rsa_public_key = await self.wait_for_message()
        rsa_public_key = rsa_public_key.decode("utf-8")
        self.aeskey = get_random_bytes(16).hex().encode("utf-8")
        encrypted_aes_key = self.encrypt_data(rsa_public_key, self.aeskey)

        test_message = await self.send_message(self.serialize(encrypted_aes_key))
        decrypted_test_message = self.decrypt_aes_data(self.aeskey, test_message)

        if not decrypted_test_message.get("text") == "TestEncryptionMessage":
            exit("Failed")

        self.encrypted = True

        reversed_fill = decrypted_test_message.get("fill")[::-1]
        msg = {"text": "TestEncryptionMessageResponse", "fill": reversed_fill}
        await self.send_message(self.serialize(msg), False)

    async def get_connection(self):
        print(f"Opening connection to {self._address} on port {self._port}")
        retries = 3

        for n in range(retries):
            con = asyncio.open_connection(self._address, self._port)
            try:
                self.reader, self.writer = await asyncio.wait_for(con, timeout=3)

                break

            except asyncio.TimeoutError:
                print(f"Timeout error connecting to {self._address}")
                await asyncio.sleep(n)
            except ConnectionError:
                print(f"Connection error connecting to {self._address}")

    def connected(self):
        return self._connected

    def decrypt_aes_data(self, key, data: bytes):
        """
        Accept out cipher text object
        Decrypt data with AES key
        """
        try:
            jdata = json.loads(data.decode("utf-8"))
            nonce = bytes.fromhex(jdata["nonce"])
            tag = bytes.fromhex(jdata["tag"])
            ciphertext = bytes.fromhex(jdata["ciphertext"])

            # let's assume that the key is somehow available again
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            msg = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise
        return json.loads(msg)

    def encrypt_aes_data(self, key, message: bytes) -> str:
        """
        Take a json object, dump it in plain text
        Encrypt message with AES key
        Create a json object with the cipher text and digest
        Then return that object in plain text to send to our peer
        """
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        jdata = {
            "nonce": cipher.nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex(),
        }
        return json.dumps(jdata).encode("utf-8")

    async def wait_for_message(self):
        while True:
            # ToDo: make this error handling a bit better. E.g. if authentication fails,
            # this error will get raised instead of letting the client know
            try:
                data = await self.reader.readuntil(separator=self.seperator)
            except asyncio.IncompleteReadError as e:
                exit(repr(e))
            message = data.rstrip(self.seperator)
            if self.encrypted:
                message = self.decrypt_aes_data(self.aeskey, message)
                message = json.dumps(message).encode()

            return message

    async def check_encryption_and_send(self, message, expect_reply=True):
        if self.encrypted:
            message = self.encrypt_aes_data(self.aeskey, message)

        encoded = json.dumps(message).encode("utf-8")
        return await self.send_message(encoded, expect_reply)

    async def send_message(self, message: bytes, expect_reply: bool = True):
        if self.encrypted:
            print("Sending encrypted message")
            message = self.encrypt_aes_data(self.aeskey, message)
        else:
            print("Sending message in the clear")

        self.writer.write(message + self.seperator)
        await self.writer.drain()

        if expect_reply:
            return await self.wait_for_message()

    async def close_socket(self):
        self.writer.write_eof()
        self.writer.close()
        await self.writer.wait_closed()

    def __del__(self):
        if self.writer and not self.writer.is_closing():
            print("Closing socket")
            self.loop.run_until_complete(self.close_socket())
            self.loop.close()
