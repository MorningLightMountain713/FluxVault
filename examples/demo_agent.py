import asyncio
import logging
import time

from fluxvault import FluxAgent
from fluxvault.extensions import FluxVaultExtensions

vault_log = logging.getLogger("fluxvault")
aiotinyrpc_log = logging.getLogger("aiotinyrpc")
level = logging.DEBUG

formatter = logging.Formatter(
    "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
)

vault_log.setLevel(level)
aiotinyrpc_log.setLevel(level)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
file_handler = logging.FileHandler("keeper.log", mode="a")
file_handler.setFormatter(formatter)

vault_log.addHandler(stream_handler)
aiotinyrpc_log.addHandler(stream_handler)


# the extension allows these functions to be called from the remote end, to see
# what functions are available on the remote end call get_methods (from the keeper)
extensions = FluxVaultExtensions()

# this will run on the main loop as it's async (preferred), works with any async
# library, i.e. aiohttp, aiomysql, etc
@extensions.create
async def async_demo():
    # docstring is included in the `get_methods` call
    """Demo async friendly function"""
    await asyncio.sleep(5)
    return "Hello World!"


# this will run in a thread as it's sync (ain't nobody got time for that)
@extensions.create
def sync_demo():
    time.sleep(5)
    return "I blocked for 5 seconds"


agent = FluxAgent(
    extensions=extensions,
    working_dir="/tmp",
    managed_files=["quotes.txt", "secret_password.txt"],
)

# all options

# agent = FluxAgent(
#     bind_address="127.0.0.1",
#     bind_port=8888,
#     dispatcher=dispatcher,
#     working_dir="/tmp",
#     managed_files=["blah.txt"],
#     whitelisted_addresses=["127.0.0.1"],
#     authenticate_vault=True,
# )

agent.run()
