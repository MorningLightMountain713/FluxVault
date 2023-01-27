import asyncio
import logging

from fluxvault import FluxKeeper, FluxVaultExtensions

log = logging.getLogger()
formatter = logging.Formatter(
    "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
)
log.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

log.addHandler(stream_handler)


extensions = FluxVaultExtensions()


def manage_transport(f):
    async def wrapper(*args, **kwargs):
        agent = kwargs.get("agent")
        await agent.transport.connect()

        if not agent.transport.connected:
            log.info("Transport not connected... skipping.")
            return {}

        res = await f(*args, **kwargs)
        await agent.transport.disconnect()

        return res

    return wrapper


async def add_agent_to_proxy(reader, writer):
    """This is web ssh shit, just need to replace the ssh part with the socket"""
    pass


@extensions.create(pass_context=True)
async def start_agent_shell(ctx):
    for address, agent in ctx.agents.items():
        await agent.transport.connect()

        if not agent.transport.connected:
            log.info("Transport not connected... skipping.")
            return

        # sockname is local, peername is remote
        target = agent.transport.writer.get_extra_info("sockname")
        print(type(target))
        print(target)
        agent_proxy = agent.get_proxy()
        # agent_proxy.raw_socket = True
        # this start shell will start subprocess and hook the reader / writer to the
        # shell. All commands from this point are at the shell. (Once we've received response)
        reply = await agent_proxy.connect_shell(target)
        print("reply", reply)

        if True:  # this means shell is hooked up at the other end
            # agent.transport.proxy_to_socketio()
            while True:
                await asyncio.sleep(0.01)
            # if not hasattr(ctx, "queue"):
            #     ctx.queue = await agent.transport.send_raw(b"ls -la\n")

            # while True:
            #     # this should send back a queue or something and we fish data out of it
            #     try:
            #         res = ctx.queue.get(block=False)
            #     except queue.Empty:
            #         await asyncio.sleep(0.01)
            #     if res:
            #         print("res")
            #         print(res)

            # await keeper.add_agent_to_proxy(address)
            # await keeper.wait_finished_proxy(address)
            # does the above deal with the transport.disconnect() ??


keeper = FluxKeeper(
    extensions=extensions,
    vault_dir="examples/files",
    comms_port=8888,
    agent_ips=["127.0.0.1"],
    console_server=True,
)


loop = asyncio.get_event_loop()
loop.run_forever()
# loop.run_until_complete(keeper.start_agent_shell())

try:
    loop.run_forever()
finally:
    pass
