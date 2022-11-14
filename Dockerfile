# syntax=docker/dockerfile:1.3-labs

FROM python:3.9-bullseye

RUN pip install fluxvault

WORKDIR /app

RUN <<EOF
echo 'from aiohttp import web
async def handle(request):
    name = request.match_info.get("name", "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)
app = web.Application()
app.add_routes([web.get("/", handle),
    web.get("/{name}", handle)])
if __name__ == "__main__":
    web.run_app(app)' > myapp.py
EOF

RUN echo "#!/bin/bash\nfluxvault agent &\npython myapp.py" > entrypoint.sh

RUN chmod +x entrypoint.sh

ENTRYPOINT [ "/app/entrypoint.sh" ]
