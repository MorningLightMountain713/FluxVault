from aiohttp import web
import asyncio
from pathlib import Path


async def index(request):
    print("received request")
    """Serve the client-side application."""
    with open("dist/index.html") as f:
        return web.Response(text=f.read(), content_type="text/html")


async def fav(request):
    print("received request")
    """Serve the client-side application."""
    data = Path("dist/favicon.ico").read_bytes()
    return web.Response(body=data, content_type="image/png")


async def main():
    app = web.Application()
    app.add_routes([web.static("/css", "dist/css")])
    app.add_routes([web.static("/js", "dist/js")])
    app.add_routes([web.static("/img", "dist/img")])
    app.add_routes([web.static("/fonts", "dist/fonts")])

    app.router.add_get("/", index)
    app.router.add_get("/favicon.ico", fav)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8888)
    await site.start()
    await asyncio.Event().wait()


asyncio.run(main())
