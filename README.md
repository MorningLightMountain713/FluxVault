# FluxVault
Flux Vault - load private data into a running container.

This package provides a way to securely load passwords and private data into a running Flux application / container(s). All data passed into a container is encrypted, so no one can snoop on you data. However, data is not stored on disk encrypted. Please remember, the node owner still has root access to your container, and can access any files / data.

If you just want to have at it - please skip to the `quickstart` section below.

## How does it work?

Flux vault has two pieces - The `agent` that runs on a Fluxnode as part of your application, and the `keeper` that runs in your secure environment (usually your home computer or server).

It is important that no one else has access to your secure environement - this is where your private data is located.

The `agent` runs in the background on the Fluxnode, waiting for the `keeper` to connect. The agent is either installed on your app component, or run as a companion component that will securely serve files to your other components.

You then run the `keeper` in your environment. You have a couple of options here - you can manually run it periodically, or you can run it as a service in the background. The agent will run in the background and update nodes continuously. (Every 10 minutes by default)

---

## Quickstart

Installation:

* Requires Python 3.9 or later

```
pip install fluxvault
```

This will give you access to the `fluxvault` application.

![fluxvault main](https://github.com/MorningLightMountain713/FluxVault/blob/feature/async_rpc/fluxvault_main.png?raw=true)

### Agent

Flux Vault agent can either be run as a companion component for your application, or you can integrate it into your existing application.

### Fluxvault - Integrate into your existing application

Running the agent:

A simple agent setup would look like this: (see Agent section for more detailed explanation)

```
fluxvault agent --whitelisted-addresses <your home ip> --managed-files secret_password.txt
```

This will run the `agent`, listening on port 8888, allowing the `keeper` access from your home ip address only. Once the `keeper` connects, the file `secret_password.txt` will end up in the agents working dir (`/tmp` by default) 

It's then up to your application to make use of the `secret_password.txt` file.

A simple Dockerfile might look like this:

```
FROM python:3.9-bullseye

RUN pip install fluxvault

RUN fluxvault agent &

EXPOSE 8888

CMD ["your app stuff"]
```

Running the container:

Every configuration option available for `fluxvault` can either be specified on the command line or via environment variables. If using env vars, all options are prefixed with `FLUXVAULT_`. For example, to start the container above we could do the following:

```
 docker run -e FLUXVAULT_WHITELISTED_ADDRESSES=<your ip>,<your other ip> -e FLUXVAULT_MANAGED_FILES=secret_password.txt -it yourrepo/container:latest
```

### Fluxvault - running as a Companion component

Add this container to your Flux application

`megachips/fluxvault:latest` *TBD - update to runonflux

Specify environement variables for configuration, at a minimum, you will need the following, see later sections for more info.

FLUXVAULT_WHITELISTED_ADDRESSES - comma seperated list of ip addresses

FLUXVAULT_MANAGED_FILES - comma seperated list of files you want delivered

FLUXVAULT_FILESERVER - True, will enable the local http fileserver

Your fluxvault component will now serve files locally to your other components via http. It validates the container names to ensure only your app gets served the secret files. It also ensures it only serves to private addresses in case you accidentally open the port to the public.

```
curl flux<component_name>_<app_name>:2080/files/<managed file>
```

If the `keeper` has not delivered the files yet - the local fileserver will respond with a `503 - service unavailable` HTTP response.

### Keeper

The Keeper is run in your secure environment. Local server or home computer.

If you are on a unix like system and want the `keeper` to run in the background, the easiest way is to use a process supervisor like systemd and create a service.

Here is an example systemd service file:

```
[Unit]
Description=Flux Vault

[Service]
ExecStart=/usr/local/bin/fluxvault keeper --vault-dir /tmp/vault --app-name <app name>

[Install]
WantedBy=multi-user.target
```

Add the content to /etc/systemd/system/fluxvault.service

reload systemd

`sudo systemctl daemon-reload`

Windows has process supervisors and should work with Flux Vault, however they have not been tested.

Choose a directory you want to use as your `vault` directory. For example, we will use /tmp/vault here.

Add your secret password file to the /tmp/vault directory.

```
echo "supersecretpassword123" > /tmp/vault/secret_passwords.txt
```

Start the `keeper` and connect to all agents.

```
fluxvault keeper --vault-dir /tmp/vault --app-name <your-app-name>
```

The keeper will now connect to all agents and deliver any requested files!

By default the `keeper` will connect every 10 minutes. This is configurable.

### Global configuration options

  * log_to_file - True. Enables file logging.
  * logfile_path - the full path of where you want the logfile. By default logs to current directory `fluxvault.log`
  * debug - shows extra debug logging. Be aware - this will decrypt messages and print to log file.

### Agent specific configuration options

All options are able to be passed as an environment variable. Just prefix the option name with FLUXVAULT_ (all option names in capitals)

  * bind_address - the address the agent listens on. 0.0.0.0 by default.
  * bind_port - the port to listen on. 8888 by default.
  * enable_local_fileserver - for multicomponent apps. If you want to share the secret files to other components.
  * local_fileserver_port - the port to serve files on. 2080 by default.
  * managed_files - comma seperated string of files you want the keeper to provide to the application.
  * working_dir - where the files will be stored locally.
  * whitelisted_addresses - comma seperated string of ip addresses that are allowed to talk to the agent. (your home ip address)
  * disable_authentication - Development only - don't do this on a real app.

### Keeper specific configuration options

Same as the agent - all options work as environment variables

  * vault_dir - the directory that contains your secret files. Default to ./vault 
  * comms_port - what port to use to connect to agent. Default 8888
  * app_name - the name of your flux application (the keeper will look up your app and get the agent ip addresses)
  * polling_interval - how often to poll agents. Default 300 seconds
  * run_once - If you don't want to poll agent and just run once
  * agent_ips - development, if specified, will try to contact addresses specified only. App name is ignored.

## Using the fluxvault library in your application

If your application is written in Python, you may want to import the fluxvault library directly and use this in your applcation.

Here is a demo of how you may do that:
```
from fluxvault import FluxAgent

  agent = FluxAgent(
      managed_files=["secret_password.txt"],
      working_dir="/app/passwords",
      whitelisted_addresses=["your keeper ip address"],
  )

  agent.run()
```

OR if you want to run asynchronously:

```
import asyncio
from fluxvault import FluxAgent

agent = FluxAgent(
    managed_files=["secret_password.txt"],
    working_dir="/tmp",
    whitelisted_addresses=["your keeper ip address"],
)

loop = asyncio.get_event_loop()
loop.create_task(agent.run_async())

try:
    loop.run_forever()
finally:
    agent.cleanup()

```

## Advanced usage

### Authentication and Message signing

Since version 0.1.13 - it is now possible for the app owner to authenticate the Keeper to the Agents by signing a message - basically using your Zelid. The same as logging in to deploy an app on Flux.

One drawback of limiting the source IPs of the Keeper(s) that are allowed to connect to the Agent is that you have to put these IPs into an ENV var that is viewable be everyone - meaning everyone can see the IP address of your Keeper. If you don't want to do that, you can now disable IP whitelists and move to message signing, where every connection from the Keeper to the agent is authenticated.

You will need your Zelid private key in order to do this. Couple of options here. The recommended way is to run the app via the CLI - it will prompt you for your Zelid and securely store this in your systems secure storage area. On macOS this is the keychain, on Windows this is credential manager and Unix based flavours have their own mechanisms.

Once stored securely, every time you need the Keeper, you just enter you Zelid (to find the key in storage) and you no longer need to enter your key.

If desired, as an added layer of security, you can add both message signing and source ip verification.

Here is an example of how to configure message signing via the CLI.

Agent:

```
fluxvault agent --manage-files quotes.txt --signed-vault-connections
```

* Note, for development, you can pass in the Zelid on the agent if it won't be running on a Fluxnode (normally the agent would get the zelid of the app owner from the Flux network)

Keeper:

```
fluxvault keeper --vault-dir examples/files --sign-connections --zelid 1GKugrE8cmw9NysWFJPwszBbETRLwLaLmM
```

For the Keeper, you must pass in the Zelid in order to store the private key against. This means you can have multiple private keys stored securely.

Once the keeper is started, it will prompt you for your private key, as seen below.

```
** WARNING **

You are about to enter your private key into a 3rd party application. Please make sure your are comfortable doing so. If you would like to review the code to make sure your key is safe... please visit https://github.com/RunOnFlux/FluxVault to validate the code.

 Please enter your private key (in WIF format):

Would you like to store your private key in your device's secure store?

(macOS: keyring, Windows: Windows Credential Locker, Ubuntu: GNOME keyring.

 This means you won't need to enter your private key every time this program is run. [Yes] y
 ```

## Development

Fluxvault is formatted using black and isort, and built with poetry.

To contribute, clone this repo, then pip install poetry.
