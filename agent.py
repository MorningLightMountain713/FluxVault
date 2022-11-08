import asyncio
import time

from aiotinyrpc.dispatch import RPCDispatcher

from fluxvault import FluxAgent

# the dispatcher allows these functions to be called from the remote end, to see
# what functions are available on the remote end call get_methods (from the keeper)
extensions = RPCDispatcher()

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
    whitelisted_addresses=["172.17.0.1"],
    extensions=extensions,
    working_dir="/app",
    managed_files=["app.tar.gz"],
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
