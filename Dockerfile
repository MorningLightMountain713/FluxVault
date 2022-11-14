# syntax=docker/dockerfile:1.3-labs

# Simple webserver example, this will return a 404 before the keeper is run, and after
# it will display the secret file

# Assumes you are using the default working_dir, /tmp and the managed_files, quotes.txt

# docker run -p 8080:8080 -p 8888:8888 -e FLUXVAULT_WHITELISTED_ADDRESSES=127.0.0.1 -e FLUXVAULT_MANAGED_FILES=quotes.txt --name fluxcomponent1_app1 -it <YOUR IMAGE NAME>




# Depending on your platform, if you're running this in development locally, your keeper address can change.
# Just let it error and update the whitelisted address

FROM python:3.9-bullseye

RUN pip install fluxvault

WORKDIR /app

RUN <<EOF
echo 'import os
from aiohttp import web
async def handle(request):
    file_path = "/tmp/quotes.txt"
    if not os.path.exists(file_path):
        return web.Response(
            body="Example quotes file does not exist. Have you run the keeper?",
            status=404,
        )
    with open(file_path, "r") as f:
        data = f.read()
        out = f"Here is your secret data - normally you would keep this hidden\\n\\n{data}"
    return web.Response(
        body=out
    )
app = web.Application()
app.add_routes([web.get("/", handle),
    web.get("/{name}", handle)])
if __name__ == "__main__":
    web.run_app(app)' > myapp.py
EOF

RUN echo "#!/bin/bash\nfluxvault agent &\npython myapp.py" > entrypoint.sh

RUN chmod +x entrypoint.sh

ENTRYPOINT [ "/app/entrypoint.sh" ]
