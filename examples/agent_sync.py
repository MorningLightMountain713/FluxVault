"""Simple example with logging of running fluxagent synchronously"""

from fluxvault import FluxAgent
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s: %(name)s: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)

agent = FluxAgent(
    managed_files=["secret_password.txt"],
    working_dir="/tmp",
    whitelisted_addresses=["127.0.0.1"],
)

agent.run()
