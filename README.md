# FluxVault
Flux Vault - load private data into running docker

The goal of this is to provide a way to securely load passwords on a running Flux Docker

vault.py defines two Classes FluxAgent and FluxNode an application can create a custom class
which will allow configurating and also expanding the functionality.

The FluxNode runs on a Flux Node as a small server waiting for the FluxAgent to connect.
The FluxAgent periodically connects to each of the nodes it supports the handle any
requests the nodes may have.

Presently the only action supported is requesting a file from the agent.

If a custom class is created additional actions can be added where the agent
truely acts as an agent for the node, one example might be the node sending a CSR
and the agent contacting letsencrypt to generate a certificate for the node.

In my use case the Agent is in my Home LAN and the Nodes are running on Flux

The Node will only accept connections from a predefined host name, which could be controlled by dyn-dns

The Agent will query FluxOS to determine what IP addresses are running the application the Agent supports.
The Agent will connect to the nodes periodically to see if they need any files sent securely.

This is not designed to send large files, just simple configuration files and passwords

The communication flow is as follows:

1. Agent connects to Node on a predefined Application port.
2. The Node will generate a RSA Key Pair and send the Public Key to the Agent.
3. The Agent will use that Public Key to encrypt a message that contains an AES Key
4. The Node will send a test message using the provided AES Key to the Agent
5. If the Agent suceesfully decrypts the message it sends a Test Passed message, also encrypted.
   (All further messages are encrypted with this AES Key)
6. The Node will send Request a message for a named file
7. The Agent will return the contents of that file if it is missing or has changed or an error status

Steps 6-7 repeat until the Node needs nothing else and sends a DONE message.
Note: Steps 6-7 can be any defined action the Node needs the Agent to perform.

At the socket level the messages are JSON strings terminated with Newline. Presently the maximum length of the JSON message is 8192, this could be increased but the data is limited to a single JSON structure.

It is a simple proof of concept that can clearly be improved as well as implemented in other langauges as needed.

One big area of improvement is in step 2, it would be valuable if the Application could have the message containing the Public Key be signed by the Flux Node it is running on and then the Agent would have greater assurance the message was valid.

# Dependencies

The code was written to Python 3

It uses the following python libraries

- from Crypto.PublicKey import RSA
- from Crypto.Random import get_random_bytes
- from Crypto.Cipher import AES, PKCS1_OAEP
- import binascii
- import json
- import sys
- import os
- import time

Crypto is obtained from the pycryptodome library, installed with 

pip3 install pycryptodome

The rest are standard python libraries

# Installation

Both Ubuntu Desktop 20.04 and 22.04 have python3 preinstalled.
Installing pycryptodome needs pip3 also installed which can be done with this command:

sudo apt install python3-pip

You can then run

pip3 install pycryptodome

You will likely need git to checkout the code (required to run the demo)

sudo apt install git
git clone https://github.com/RunOnFlux/FluxVault.git

Install python library

pip3 install ./FluxVault

(When beta testing is complete this library will be deployed as a python package and installed with 'pip3 install fluxvault')

Windows

TODO

Flux Node

Typically the Agent will be running on a Desktop and the Node will be on a Flux Node.
You will need to include the code in your docker image

In application I used alpine:3.15 and the command to add python3 to docker are

# Python
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools
RUN apk add gcc g++ make libffi-dev openssl-dev git
RUN pip3 install pycryptodome
RUN pip3 install requests


TODO

So far the code has only been run on Ubuntu systems, it should easily run under WSL.
Python is very portable, there should not be any reason it would not run on Windows or Mac directly.

# Demo

There are two demo files vault_agent.py and vault_node.py that can be used to demonstrate the sending of secrets.

1) Clone the repo to a local directory
2) Open two terminal windows in that same location
3) Create a temp folder: "mkdir /tmp/node" This is where files will be written/updated
4) Inspect the two scripts, they have a MyFluxNode/MyFluxAgent class that defines all the configuration for the demo ("EDIT ME")
5) In one terminal start the Node server "python3 ./vault_node.py" This starts a server that does not exit.
6) In the other terminal run the Agent "python3 ./vault_agent --ip 127.0.0.1" The Agent will contact the Node at the IP given

If you edit or delete one of the files in /tmp/node and re-run vault_agent the file will be re-sent.

The Agent will run once and exit, if the --ip is left off then the vault_agent.py code looks for named Flux Application
and contacts the Node server running on each active instance of the named application.

In my use case I run the Agent once an hour, in a custom vault_agent.py the it could check the Flux App list every 5 or 10 minutes
and then contact new nodes right away and other nodes at a slower rate.

The vault_node.py code uses a python ThreadedServer to wait for connections, a custom implementation could do something totally
different, possibly adding the calls to an existing application.

## Result Output

The output of vault_node.py will look like this:

tom@mini1:~/FluxVault$ ./vault_node.py 
Running in Demo Mode files will be placed in  /tmp/node/
Warning  /tmp/node/  exists
node_server  localhost
The NodeKeyClient server is running on port 39898
Connected: ('127.0.0.1', 58910) on Thread-1
quotes.txt  received!
readme.txt  received!
Closed: ('127.0.0.1', 58910) on Thread-1

The output of vault_agent.py will look like this:

tom@mini1:~/FluxVault$ ./vault_agent.py --ip 127.0.0.1
 Connecting to server, 127.0.0.1 (127.0.0.1)
File  quotes.txt  sent!
File  readme.txt  sent!
127.0.0.1 Completed
tom@mini1:~/FluxVault$ 


# Customization

The sequence of defines actions is as follows:

1) The Agent connects to a Node and sets up a secure connection
2) The Node runs FluxNode.agent_action which processes any response from the Agent and then calls FluxNode.user_request
3) FluxNode.user_request gets called with a step counter and the custom code can invoke FluxNode.request_file or any request function added in MyFluxNode
4) The request function formatted and encrypted a request that is sent to the Agent
5) The Agent receives the request and uses the 'State' field of the message to lookup the function to handle the request
6) The function can be FluxAgent.node_request or any function defined in MyFluxAgent and added to MyFluxAgent.agent_action
7) The agent_action function processes the request and sends the response to the Node which brings us back to #2 above
8) When the Node has completed all the requests, it sends the 'DONE' action which will signal the Agent to disconnect

# TODO

- Write code to periodically poll FluxOs for a list of nodes and see if aany need config
- Explore a Windows GUI solution, right now it is command line only (Only tested on Ubuntu)