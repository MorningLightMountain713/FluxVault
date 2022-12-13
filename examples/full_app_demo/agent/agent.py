import asyncio
import logging

from fluxvault import FluxAgent

log = logging.getLogger()
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s: %(name)s: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)


if __name__ == "__main__":
    agent = FluxAgent(
        signed_vault_connections=True,
        zelid="1GKugrE8cmw9NysWFJPwszBbETRLwLaLmM",
    )

    agent.run()
