"""Example expecting signed keeper messages"""

import logging

from fluxvault import FluxAgent

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
    signed_vault_connections=True,
    zelid="1GKugrE8cmw9NysWFJPwszBbETRLwLaLmM",
)

agent.run()
