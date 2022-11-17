"""Example showing how to run the keeper and check if they need any files"""

import logging
import time

from fluxvault import FluxKeeper

polling_interval = 300

### BEWARE ###
#
# these are real. You are welcome to use them for testing, however do not use these
# addresses for transactions
key = "Kwd2NvAavdEjYFWj299R6csDyoFeQsLvH5ZkN1Bb8jQcf1e8Qre7"
zelid = "1GKugrE8cmw9NysWFJPwszBbETRLwLaLmM"


log = logging.getLogger()
formatter = logging.Formatter(
    "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
)
log.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

log.addHandler(stream_handler)


keeper = FluxKeeper(
    vault_dir="examples/files",
    comms_port=8888,
    agent_ips=["127.0.0.1"],
    signing_key=key,
)

while True:
    keeper.poll_all_agents()
    log.info(f"sleeping {polling_interval} seconds...")
    time.sleep(polling_interval)
