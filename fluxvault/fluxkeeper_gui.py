# Standard library
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import socketio
import time

# this is to prevent circular import from type checking an init
if TYPE_CHECKING:
    from fluxvault.fluxkeeper import FluxKeeper

from dataclasses import dataclass, field
from pathlib import Path

from aiohttp import web

# this package
# from fluxvault.fluxkeeper import FluxKeeper
from fluxvault.log import log


@dataclass
class FluxKeeperGui:
    address: str
    port: int
    keeper: FluxKeeper
    root_dir: Path = field(default_factory=Path)
    app: web.Application = field(default_factory=web.Application)
    sio: socketio.AsyncServer = field(
        default_factory=lambda: socketio.AsyncServer(cors_allowed_origins="*")
    )
    namespace: str = "/pty"

    @staticmethod
    async def index(request):
        print("received request")
        """Serve the client-side application."""
        with open("index.html") as f:
            return web.Response(text=f.read(), content_type="text/html")

    async def start(self):
        if not self.root_dir.is_absolute():
            current_dir = Path().resolve()
            self.root_dir = current_dir / self.root_dir

        self.sio.attach(self.app)
        self.app.router.add_get("/", self.index)

        self.sio.on("connect", self.client_connect, self.namespace)
        self.sio.on("pty_connect", self.pty_connect, self.namespace)
        self.sio.on("pty_input", self.pty_input, self.namespace)
        self.sio.on("resize", self.resize_pty, self.namespace)
        self.sio.on("terminal_closed", self.close_terminal, self.namespace)

        # ToDo: maybe do something with access logs
        runner = web.AppRunner(self.app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, self.address, self.port)
        await site.start()
        log.info("Console server running on http://127.0.0.1:7777")

    async def client_connect(self, sid, environ):
        log.info(f"Browser connected to SocketIO, sid: {sid}")
        await self.network_state_update()

    async def pty_connect(self, sid, data):
        target = data.get("host")
        log.info(f"Connecting pty for client: {target}")
        agent = self.keeper.agents.get_by_id(target)
        # ToDo: remove
        agent.sid = sid

        # ToDo: this could break now, since were managing auth params
        await agent.transport.connect()

        if agent.proxy_host_port:
            target = agent.proxy_host_port
        else:
            target = agent.transport.writer.get_extra_info("sockname")

        agent_proxy = agent.get_proxy()
        agent_proxy.one_way = True
        await agent_proxy.connect_shell(target)
        await self.sio.emit(
            "pty_connected",
            agent.id,
            namespace=self.namespace,
        )
        log.info("pty_connected sent")

    async def pty_input(self, sid, data):
        print("received pty_input", data)
        target = data.get("host")
        input = data.get("input")
        agent = self.keeper.agents.get_by_id(target)
        transport = agent.transport

        await transport.send_pty_message(data=input.encode())

    async def pty_output(self, local_socket, data):
        agent = self.keeper.agents.get_by_socket(local_socket)
        try:
            await self.sio.emit(
                "pty_output",
                {"id": agent.id, "output": data.decode()},
                namespace="/pty",
            )
        except Exception as e:
            print(repr(e))

    async def resize_pty(self, sid, data):
        log.info(
            f"Sending resize message via transport to remote pty. Size: {data['rows']}x{data['cols']}"
        )
        target = data.get("host")
        agent = self.keeper.agents.get_by_id(target)
        transport = agent.transport

        await transport.send_pty_resize_message(data["rows"], data["cols"])

    async def app_state_update(self, app_name, state):
        start = time.monotonic()
        log.info("Sending network state update to browser")
        await self.sio.emit("app_state", {app_name: state}, namespace="/pty")
        log.info(f"Time to send sio update: {time.monotonic() - start}")

    async def start_keeper(self, *args, **kwargs):
        pass

    async def pty_closed(self, local_socket):
        log.info("Remote pty is closed. Disconnecting and notifying browser...")
        agent = self.keeper.agents.get_by_socket(local_socket)
        await agent.transport.disconnect()
        await self.sio.emit("pty_closed", agent.id, namespace="/pty")

    async def close_terminal(self, sid, data):
        print("closing pty", data)
        # ToDo: Update host to id
        id = data.get("host")
        agent = self.keeper.agents.get_by_id(id)
        if agent.is_proxied:
            our_socket = agent.proxy_host_port
        else:
            our_socket = agent.transport.writer.get_extra_info("sockname")
        proxy = agent.get_proxy()

        await proxy.disconnect_shell(our_socket)

    async def set_toast(self, toast):
        log.info("Sending toast update to browser")
        await self.sio.emit("toast_update", {"toast": toast}, namespace="/pty")
