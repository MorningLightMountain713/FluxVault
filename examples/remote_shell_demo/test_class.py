from dataclasses import dataclass
from aiohttp import web
import socketio
import asyncio
from typing import Callable


@dataclass
class ConsoleServer:
    address: str
    port: int
    agents: dict
    app: web.Application = web.Application()
    sio: socketio.AsyncServer = socketio.AsyncServer(cors_allowed_origins="*")
    namespace: str = "/pty"

    async def start(self):
        self.sio.attach(self.app)

        self.sio.on("pty_input", self.pty_input, self.namespace)

        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.address, self.port)
        await site.start()

    async def emit(self):
        print("emitting")
        await self.sio.emit("pty_output", {"output": "Hi there!"}, namespace="/pty")

    @sio.event(namespace=namespace)
    def connect(sid, environ):
        print(f"Connected, sid: {sid}")

    async def pty_input(self, sid, data):
        print("received pty_input", data)
        target = data.get("target")
        agent = self.agents.get(target)
        writer = agent.transport.writer
        writer.write(data)
        await writer.drain()


async def main():
    console = ConsoleServer("localhost", 7777, {"127.0.0.1": "blah"})
    await console.start()
    while True:
        await asyncio.sleep(5)
        await console.emit()
    await asyncio.Event().wait()


asyncio.run(main())
