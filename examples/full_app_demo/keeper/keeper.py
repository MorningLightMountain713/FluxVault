"""Example showing how to extend the Keeper for your own needs"""

import asyncio
import logging
import secrets
import sys

from fluxvault import FluxKeeper
from fluxvault.extensions import FluxVaultExtensions
from fluxvault.helpers import manage_transport

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


@manage_transport
async def stop_worker(agent):
    agent_proxy = agent.get_proxy(plugins=["vanity_finder"])
    await agent_proxy.vanity_finder.stop_workers()


@extensions.create(pass_context=True)
async def stop_workers(ctx):
    tasks = []
    for agent in ctx.agents:
        tasks.append(asyncio.create_task(stop_worker(agent=agent)))
    await asyncio.gather(*tasks)


@manage_transport
async def check_worker(agent):
    agent_proxy = agent.get_proxy(plugins=["vanity_finder"])
    reply = await agent_proxy.vanity_finder.check_workers()
    return reply


@extensions.create(pass_context=True)
async def check_workers(ctx):
    tasks = []
    for agent in ctx.agents:
        tasks.append(asyncio.create_task(check_worker(agent=agent)))
    results = await asyncio.gather(*tasks)
    return results


@extensions.create(pass_context=True)
async def start_workers(ctx, passphrase, vanity):
    @manage_transport
    async def start_worker(agent):
        # plugins can be found with agent_proxy.list_server_details()
        agent_proxy = agent.get_proxy(plugins=["vanity_finder"])
        agent_details = await agent_proxy.list_server_details()
        agent_working_dir = agent_details.get("working_dir")
        file = f"{agent_working_dir}/runner"

        agent_proxy.vanity_finder.one_way = True
        await agent_proxy.vanity_finder.run_file(file, ["hdwallet"], passphrase, vanity)
        agent_proxy.vanity_finder.one_way = False

    tasks = []
    for agent in ctx.agents:
        tasks.append(asyncio.create_task(start_worker(agent=agent)))
    await asyncio.gather(*tasks)


@extensions.create(pass_context=True)
async def load_agents_plugins(ctx, directory):
    @manage_transport
    async def load_agent_plugins(agent):
        agent_proxy = agent.get_proxy()
        await agent_proxy.load_plugins(directory=directory)

    tasks = []
    for agent in ctx.agents:
        tasks.append(asyncio.create_task(load_agent_plugins(agent=agent)))
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
        managed_files=["runner.py", "vanity_finder.py:plugins/vanity_finder.py"],
        comms_port=8888,
        agent_ips=["192.168.4.27"],
        sign_connections=True,
        signing_key=key,
    )

    await keeper.run_agent_tasks()
    await keeper.load_agents_plugins(directory="plugins")
    await keeper.start_workers(passphrase, vanity)
    await asyncio.sleep(30)

    try:
        # this is ugly
        solution = None
        for _ in range(5):
            results = await keeper.check_workers()
            for result in results:
                solution = result.get("result")
                if solution:
                    print(f"Solved! Data: {solution}")
                    break
                else:
                    print(f"Best match: {result.get('best')}")
            if solution:
                break
            await asyncio.sleep(30)

    finally:
        await keeper.stop_workers()


asyncio.run(main())
