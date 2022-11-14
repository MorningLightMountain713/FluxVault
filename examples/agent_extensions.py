"""Example showing how to add extra methods to the agent - these can all be called
from the keeper
"""

import asyncio
import time

from fluxvault import FluxAgent
from fluxvault.extensions import FluxVaultExtensions

# the extension allows these functions to be called from the remote end, to see
# what functions are available on the remote end call get_all_agent_methods (from the keeper)
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
    whitelisted_addresses=["127.0.0.1"],
)

agent.run()
