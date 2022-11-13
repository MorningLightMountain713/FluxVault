"""Simple example with logging of running fluxagent asynchronously"""

import asyncio
from fluxvault import FluxAgent
import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s: %(name)s: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)

agent = FluxAgent(
    managed_files=["super_secret.txt"],
    working_dir="/tmp",
    whitelisted_addresses=["127.0.0.1"],
)

loop = asyncio.get_event_loop()
loop.create_task(agent.run_async())

try:
    loop.run_forever()
finally:
    agent.cleanup()
