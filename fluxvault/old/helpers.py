from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# import fluxvault.state as state

MAX_MESSAGE = 8192

import json


def encrypt_data(keypem: str, data: str) -> dict:
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


def decrypt_data(keypem: str, cipher: dict) -> str:
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


def decrypt_aes_data(key, data):
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
        return {"State": state.FAILED}
    return json.loads(msg)


def encrypt_aes_data(key, message: dict) -> str:
    """
    Take a json object, dump it in plain text
    Encrypt message with AES key
    Create a json object with the cipher text and digest
    Then return that object in plain text to send to our peer
    """
    msg = json.dumps(message)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode("utf-8"))
    jdata = {
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
    }
    data = json.dumps(jdata)
    return data


def send_receive(sock, request):
    """
    Send a request message and wait for a reply
    """
    request += "\n"

    try:
        sock.sendall(request.encode("utf-8"))
    except socket.error:
        print("Send failed")
        sys.exit()

    # Receive data
    try:
        reply = sock.recv(MAX_MESSAGE)
    except TimeoutError:
        print("Receive time out")
        return None
    reply = reply.decode("utf-8")
    return reply


# pylint: disable=W0702
def receive_only(sock):
    """
    Wait for a message from our peer
    """
    # Receive data
    try:
        reply = sock.recv(MAX_MESSAGE)
        reply = reply.decode("utf-8")
    except:
        reply = ""
    return reply


def receive_public_key(sock):
    """Receive Public Key from the Node or return None on error"""
    try:
        reply = receive_only(sock)
        print(reply)
    except TimeoutError:
        print("timeout")
        return None

    if len(reply) == 0:
        return None
    try:
        jdata = json.loads(reply)
        public_key = jdata["PublicKey"].encode("utf-8")
    except ValueError:
        return None
    return public_key
