"""Example showing how to run the keeper and check if they need any files"""

import asyncio
import logging
import secrets
import sys

from fluxvault import FluxKeeper
from fluxvault.extensions import FluxVaultExtensions

extensions = FluxVaultExtensions()

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


@extensions.create(pass_context=True)
async def stop_workers(ctx):
    async def stop_worker(agent):
        await agent.transport.connect()
        if not agent.transport.connected:
            ctx.log.info("Transport not connected... skipping.")
            return

        agent_proxy = agent.get_proxy()
        await agent_proxy.stop_workers()
        await agent.transport.disconnect()

    tasks = []
    for _, agent in ctx.agents.items():
        tasks.append(asyncio.create_task(stop_worker(agent)))
    await asyncio.gather(*tasks)


@extensions.create(pass_context=True)
async def check_workers(ctx):
    async def check_worker(address, agent):
        await agent.transport.connect()
        if not agent.transport.connected:
            ctx.log.info("Transport not connected... skipping.")
            return

        agent_proxy = agent.get_proxy()
        best = await agent_proxy.check_workers()
        print(f"Best match from {address}: {best}")
        await agent.transport.disconnect()

    tasks = []
    for address, agent in ctx.agents.items():
        tasks.append(asyncio.create_task(check_worker(address, agent)))
    await asyncio.gather(*tasks)


@extensions.create(pass_context=True)
async def start_workers(ctx, passphrase, vanity):
    async def start_worker(agent):
        await agent.transport.connect()
        if not agent.transport.connected:
            ctx.log.info("Transport not connected... skipping.")
            return

        agent_proxy = agent.get_proxy()
        agent_proxy.one_way = True
        await agent_proxy.run_file("runner", ["hdwallet"], passphrase, vanity)
        agent_proxy.one_way = False
        await agent.transport.disconnect()

    tasks = []
    for _, agent in ctx.agents.items():
        tasks.append(asyncio.create_task(start_worker(agent)))
    await asyncio.gather(*tasks)


async def main():
    args = sys.argv
    if len(args) != 2:
        print("Usage: python <this file> VANITY_STRING")
        exit(1)

    vanity = args[1]
    base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for character in vanity:
        if character not in base58:
            print("Invalid vanity string, contains non base58 characters")
            exit(1)

    passphrase = secrets.token_urlsafe()
    print(f"Passphrase: {passphrase}")

    keeper = FluxKeeper(
        extensions=extensions,
        vault_dir=".",
        comms_port=8888,
        agent_ips=["127.0.0.1"],
        sign_connections=True,
        signing_key=key,
    )

    await keeper._poll_agents()
    await keeper.start_workers(passphrase, vanity)

    try:
        for _ in range(3):
            await asyncio.sleep(30)
            await keeper.check_workers()
    finally:
        await keeper.stop_workers()


loop = asyncio.get_event_loop()

loop.run_until_complete(main())
