# syntax=docker/dockerfile:1.3-labs

# docker network create http

# old notes

#app

# docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fluxagent_demoVault

# docker run --rm --name fluxapp_demoVault --network http -p 8080:8080 -it megachips/fluxvault:keeper_app

#agent
# docker run --rm --name fluxagent_demoVault --network http -e FLUXVAULT_FILESERVER=True -e FLUXVAULT_WHITELISTED_ADDRESSES=192.168.16.4 -e FLUXVAULT_MANAGED_FILES=quotes.txt -it megachips/fluxvault:agent

#keeper
# docker run --rm --name fluxkeeper_demoVault --network http -e FLUXVAULT_VAULT_DIR=. -e FLUXVAULT_AGENT_IPS=192.168.16.3 megachips/fluxvault:keeper

FROM python:3.9-bullseye

# RUN apt update && apt install iputils-ping -y

WORKDIR /app

RUN pip install aiohttp

RUN <<EOF
echo 'from aiohttp import web, ClientSession
from aiohttp.client_exceptions import ClientConnectorError

import os
import sys

if len(sys.argv) > 1:
    agent_name = sys.argv[1]
else:
    agent_name = "fluxagent_demoVault"

async def get():
    async with ClientSession() as session:
        try:
            async with session.get(
                f"http://{agent_name}:2080/file/quotes.txt"
            ) as resp:
                data = await resp.text()
                return (resp.status, data)
        except ClientConnectorError:
            return (None, "")


async def handle(request):
    status, data = await get()

    if status == 503:
        return web.Response(
            body="Agent webserver returned 503. Have you run the keeper?",
            status=503,
        )
    elif status == None:
        return web.Response(
            body="Agent webserver was uncontactable",
            status=500,
        )
    elif status == 200:
        out = f"Here is your secret data - normally you would keep this hidden\\n\\n{data}"
        return web.Response(body=out)
    else:
        return web.Response(body=f"There was an error ({status})", status=500)


app = web.Application()
app.add_routes([web.get("/", handle), web.get("/{name}", handle)])

if __name__ == "__main__":
    web.run_app(app)' > myapp.py
EOF

ENTRYPOINT [ "python", "myapp.py" ]
