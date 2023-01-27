import asyncio

import socketio

sio = socketio.AsyncClient()


def on_message(sid, data):
    print("I received a message!")
    print(data)


sio.on("*", on_message, "/pty")


async def main():
    await sio.connect("http://localhost:7777", namespaces=["/pty"])
    print("my sid is", sio.sid)

    await sio.emit("fingerprint_agents", namespace="/pty")
    await sio.wait()


asyncio.run(main())
