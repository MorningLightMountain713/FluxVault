#!/usr/bin/python3
"""This module is a single file that supports the loading of secrets into a Flux Node"""
import socketserver
import threading
import time
import os
from fluxvault import VaultClient

BOOTFILES = ["quotes.txt", "readme.txt"]  # EDIT ME

VAULT_NAME = os.getenv("VAULT_NAME") or "localhost"
VAULT_PORT = int(os.getenv("VAULT_PORT")) or 39898
FILE_DIR = os.getenv("VAULT_FILE_DIR") or "/tmp/node/"


def start_server():
    """This server runs on the Node, waiting for the Vault to connect"""

    print("node_server ", VAULT_NAME)
    with socketserver.TCPServer(("", VAULT_PORT), TCPHandler) as server:
        print("The VaultClient server is running on port " + str(VAULT_PORT))
        server.serve_forever()


client.start_server()


if __name__ == "__main__":
    while True:
        if VAULT_NAME == "localhost" and VAULT_PORT == 39898:
            print("Running in Demo Mode files will be placed in ", FILE_DIR)
        if os.path.isdir(FILE_DIR):
            print(FILE_DIR, " exists")
        else:
            print("Creating ", FILE_DIR)
            os.makedirs(FILE_DIR)
        if os.path.exists(FILE_DIR):
            node_server()
        else:
            print(FILE_DIR, " does not exist!")
            time.sleep(60)
        print(
            "********************* node_server Exited!!!! Restarting ***********************"
        )
