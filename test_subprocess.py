import asyncio


async def run_entrypoint(entrypoint):
    # entrypoint is full script location
    proc = await asyncio.create_subprocess_shell(
        entrypoint,
    )

    await proc.communicate()


asyncio.run(run_entrypoint("/Users/davew/code/flux/fluxvault/entrypoint.sh"))
