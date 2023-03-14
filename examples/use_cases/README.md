# Use Cases

## Basic - Authentication based on source IP address

```
           Flux Application                   Pros
          ┌─────┬─┬────────┐                    * Easy to get running
          │     │┼│    ◄───┼──────Keeper        * Simple to get files to components
Agent Component └┼┘        │                    * Drop in component
          │      │http     │
          │      ▼         │                  Cons
          │  ┌─┐  ┌─┐      │                    * Insecure
          │  │┼│  │┼│      │                    * Requires components to determine when they have files
          └──┴─┴──┴─┴──────┘                    * Little control over file / directory state
          App Components
```

## Audience

This use case is suited to Fluxers who want a simple way of getting a password or two into a container, and don't care about state.

In fileserver mode, any files that are transferred are set to STRICT mode, meaning, if the file is changed, it will be overwritten again when the Keeper connects. If this doesn't work for you, check out one of the other use cases.

A shim script can be setup on your app components to fetch the files before starting the entrypoint. See example below.

## Usage

### 1/ Create file dir

These are your secret files. Create a dir and add in your secrets. They can be anything. Any file or folder structure is fine here. Plain text or binary / images etc. Just beware - whatever size your file dir is, will end up on your agents.

For example, in your current directory, make a new file dir and add a few files.

```
mkdir secrets && touch secrets/secret_file && echo \
"1844 Samuel FB Morse: What hath God Wrought?
1876 Alexander Graham Bell: Mr. Watson -- come here -- I want to see you.
2022 Dan Keller: Don't be Evil, again" > secrets/quotes.txt
```

### 2/ Create docker network

```
docker network create http
```

### 3/ Get gateway for http network

```
docker network inspect http -f '{{(index .IPAM.Config 0).Gateway}}'
```

### 4/ Start agent

Note - for the whitelist-addresses, add 2 to the gateway. So if the gatway was 172.18.0.1, we want 172.18.0.3.

You don't strictly need to expose ports, however I was running Keeper natively on macOS.

```
docker run --rm --name fluxagent_demoVault --network http -p 8888:8888 -p 2080:2080 -it megachips/fluxvault:0.8.8 agent --whitelist-addresses 172.18.0.3
```

### 5/ Start Keeper

Note, for testing, we're using a docker image here. You can also run this natively on your computer. (You will need Python 3.10 installed, venv use is recommended)

For the --agent-ips add 1 to the gateway. So for our example, would be 172.18.0.2

You need to volume mount in your fileserver dir that you created earlier. This entire directory will become available on the Agent. We mount it in, then tell the keeper where it is with the --fileserver-dir switch.

For this example, our app name is `turnip` This becomes relevant in later use cases.

```
docker run --rm --name fluxkeeper_demoVault -v $(pwd)/secrets:/data/fileserver --network http -it megachips/fluxvault:0.8.8 keeper run-single-app turnip --fileserver-dir /data/fileserver --agent-ips 172.18.0.2 --polling-interval 20
```

### 6/ Start example App

```
docker run --rm --name fluxapp_demoVault --network http -p 8080:8080 -it megachips/fluxvault-exampleapp:latest
```

### 7/ See the magic

Browse to `http://localhost:8080`

You should see the quote displayed.

### 8/ Edit quotes.txt

```
echo "2023 Hi Mom!" >> secrets/quotes.txt
```

### 9/ See the magic - again

Browse to `http://localhost:8080`

You should see the quote updated.

### 8/ How does this work?

What happened above? So the keeper transferred the files to the agent. The agent and the app reside in the same private network, so the app queried the agent via it's hostname, then served that up via a simple Python aiohttp webserver.

We then changed the quotes.txt file, which the Keeper detected, and sent the new version to the agent, which it then served up to the app over http.

# Coming soon

### The following is built, just needs tests, docs and use cases written:

Note fluxwallet is still under development and may be broken at any time

* Key management - create, view (addresses), store, delete - uses your devices secure storage area. macOS = keychain, windows = Credential Locker
* Basic - with authentication (uses bitcoin message signing)
* Basic - with authentication and agent restart protection (requires signed manifests)
* Single container apps
* Multi container apps
* Sync strategy per file or per directory. (You might want some files to be able to be modified, and some you strictly don't want changed)
* Multi app configurations, with stored config
* Proxy agent behind another agent
* Full SSL with certificates
* Full remote shell access in browser. Not ssh - custom console
* Deploy full app to Flux (uses fluxwallet) and manage it all in one