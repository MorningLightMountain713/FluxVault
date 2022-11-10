# FluxVault
Flux Vault - load private data into running container

The goal of this package is to provide a way to securely load passwords and private data
into a running Flux application / container.

vault.py defines two Classes FluxAgent and FluxNode an application can create a custom class
which will allow configurating and also expanding the functionality.

The FluxNode runs on a Flux Node as a small server waiting for the FluxAgent to connect.
The FluxAgent periodically connects to each of the nodes it supports to handle any
requests the nodes may have.

Presently the only action supported is requesting a file from the agent.

If a custom class is created additional actions can be added where the agent
truely acts as an agent for the node, one example might be the node sending a CSR
and the agent contacting letsencrypt to generate and return a certificate for the node.

In the demo use case the Agent is in a Home LAN and the Nodes are running on Flux

The Node will only accept connections from a predefined IP or a host name, which could be controlled by dyn-dns

The Agent will query FluxOS to determine what IP addresses are running the application the Agent supports.
The Agent will connect to the nodes periodically to see if they need any files sent securely.

This is not designed to send large files, just simple configuration files and passwords

The communication flow is as follows:

1. Agent connects to Node on a predefined Application port.
2. The Node will generate a RSA Key Pair and send the Public Key to the Agent.
3. The Agent will use that Public Key to encrypt a message that contains an AES Key
4. The Node will send a test message using the provided AES Key to the Agent
5. If the Agent suceesfully decrypts the message it sends a Test Passed message, which is also encrypted.
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

from Crypto.PublicKey import RSA  
from Crypto.Random import get_random_bytes  
from Crypto.Cipher import AES, PKCS1_OAEP  
import binascii  
import json  
import sys  
import os  
import time  

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

In application I used alpine:3.15 and the commands to add python3 to docker are

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

# Demo - localhost

There are two demo files vault_agent.py and vault_node.py that can be used to demonstrate the sending of secrets.

1) Clone the repo to a local directory
2) Open two terminal windows in that same location
3) By default vault_node.ps will create a temp folder in /tmp/node This is where files will be written/updated
4) Inspect the two scripts, they have a MyFluxNode/MyFluxAgent class that defines all the configuration for the demo ("EDIT ME")
5) In one terminal start the Node server "python3 ./vault_node.py" This starts a server on "The Node"
6) In the other terminal run the Agent "python3 ./vault_agent.py --ip 127.0.0.1" The Agent will contact the Node at the IP given

If you edit or delete one of the files in /tmp/node and re-run vault_agent (step 6) the file will be re-sent.

The Agent will run once and exit, if the --ip is left off then the vault_agent.py code looks for named Flux Application
and contacts the Node server running on each active instance of the named application. The script defaults to VaultDemo

In my use case I run the Agent once an hour, in a custom vault_agent.py the it could check the Flux App list every 5 or 10 minutes
and then contact new nodes right away and other nodes at a slower rate.

The vault_node.py code uses a python ThreadedServer to wait for connections, a custom implementation could do something totally
different, possibly adding the calls to an existing application.

## Result Output - Node

tom@node:/Git/FluxVault$ python3 ./vault_node.py  
Running in Demo Mode files will be placed in  /tmp/node/  
/tmp/node/  exists  
node_server  localhost  
The NodeKeyClient server is running on port 39898  
Connected: ('127.0.0.1', 49096) on Thread-1 (process_request_thread)  
quotes.txt  received!  
readme.txt  received!  
Closed: ('127.0.0.1', 49096) on Thread-1 (process_request_thread)  

## Result Output - Agent

tom@node:/Git/FluxVault$ python3 ./vault_agent.py --ip 127.0.0.1  
Oct-15-2022 07:50:46 File quotes.txt sent!  
Oct-15-2022 07:50:46 File readme.txt sent!  
127.0.0.1 Completed  
tom@node:/Git/FluxVault$   

# Demo - Local Docker

You can create a demo docker image by using my docker files:

You will need to change 192.168.X.Y to match your local machine IP address

docker run --name vault_demo --memory="1g" --cpus="1.0" -p 39289:39289 -e VAULT_PORT=39289 -e VAULT_NAME='192.168.X.Y' w2vy/vault_demo

You should see the start of the output given below.

Once the docker is running you can the run docker_demo.sh providing your local IP Addree

./docker_demo.sh 192.168.X.Y

## Result Output - Node

tom@node:/Git/FluxVault$ docker run --name vault_demo --memory=1g --cpus=1.0 -p 39289:39289 -e VAULT_PORT=39289 -e VAULT_NAME=192.168.0.123 w2vy/vault_demo  
Version 0.5 10/12/2022 p1test Vault 192.168.0.123 Port 39289  
2022/10/15 12:07:09 [notice] 7#7: using the "epoll" event method  
2022/10/15 12:07:09 [notice] 7#7: nginx/1.23.1  
2022/10/15 12:07:09 [notice] 7#7: built by gcc 11.2.1 20220219 (Alpine 11.2.1_git20220219)  
2022/10/15 12:07:09 [notice] 7#7: OS: Linux 5.15.0-48-generic  
2022/10/15 12:07:09 [notice] 7#7: getrlimit(RLIMIT_NOFILE): 1048576:1048576  
2022/10/15 12:07:09 [notice] 8#8: start worker processes  
2022/10/15 12:07:09 [notice] 8#8: start worker process 9  
2022/10/15 12:07:09 [notice] 8#8: start worker process 10  
2022/10/15 12:07:09 [notice] 8#8: start worker process 11  
2022/10/15 12:07:09 [notice] 8#8: start worker process 13  
Cloning into 'FluxVault'...  
branch 'python_class' set up to track 'origin/python_class'.  
Switched to a new branch 'python_class'  
Processing ./FluxVault  
  Preparing metadata (setup.py): started  
  Preparing metadata (setup.py): finished with status 'done'  
Requirement already satisfied: pycryptodome in /usr/lib/python3.10/site-packages (from fluxvault==1.0) (3.15.0)  
Using legacy 'setup.py install' for fluxvault, since package 'wheel' is not installed.  
Installing collected packages: fluxvault  
  Running setup.py install for fluxvault: started  
  Running setup.py install for fluxvault: finished with status 'done'  
Successfully installed fluxvault-1.0  
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv  
Creating  /tmp/node/  
node_server  192.168.0.123  
The NodeKeyClient server is running on port 39289  
Connected: ('192.168.0.123', 39736) on Thread-1 (process_request_thread)  
quotes.txt  received!  
readme.txt  received!  
Closed: ('192.168.0.123', 39736) on Thread-1 (process_request_thread)  

## Result Output - Agent

tom@node:/Git/FluxVault$ ./docker_demo.sh 192.168.0.123  
File quotes.txt Matched!  
File readme.txt Matched!  
192.168.0.123 Completed  
tom@node:/Git/FluxVault$   


# Demo - Flux Node

Since I already have w2vy/vault_demo published and whitellisted in Flux you can simply deploy the same exact demo as a Flux dApp!

In the above docker run command you can see parameters for setting the Container Name, Memory Size, CPU requirements, Port Mapping and Environment variables.

These are all the things you need to know to deploy a Flux dApp, along with the docker image name.


To deploy your own demo if the Vault you can visit https://jetpack2.app.runonflux.io/ and follow the steps:
1) Login with Zelcore
2) Click Launch
3) Fill in 'App name' (Must be unique) and 'Description', Click 'Next Step'
4) Fill in 'Component Name' (ie 'vault'), 'Docker Hub Repository for Component', must be 'w2vy/vault_demo:latest'
5) The 'Add Environment Variables' section is where we can customize the dApp settings, typically you will see NAME=VALUE, in this form there is one field for the NAME and another for VALUE and then we click 'Add' for each one.
   Set the following variables:  
   VAULT_NAME=IP-or-HOST  
   VAULT_PORT=YOUR-PORT2  
   VAULT_FILE_DIR=/usr/share/nginx/html/  

   Replace IP-or-HOST with your public IP Address (see http://whatismyip.com) or your DNS name, if you have one you will know it
   Replace YOUR-PORT with any port number between 31000 and 39999

   The demo uses 2 ports. The first port will be for the demo web server and the second port (YOUR-PORT2) the port that the Vault Agent will use to talk to the Vault Node.
6) 'Add Run Command', must be '/home/apptest/entrypoint.sh', Click 'Add'
7) Click 'Next Step'
8) 'Port Forwarding", 'Flux Public Port', Enter PORT1 and 'Docker Component Port' Enter 80 click 'Add'
9) Also enter PORT2 and PORT2 and 'Add' and 'Next Step' (You can skip Custom Domain)
10) 'How many instances will you be running?' 3 is the minimum.  
    'How many cores do you require?' It works slowly with 0.1 core, for the demo I used 0.5  
    'How much memory will your app need?' It defaults to 1000MB, I have used 500MB  
    'How much storage would you like?' The default of 1GB is fine  
11) Review the estimated cost - $0.14
12) Next Step you can review all the settings and deploy and pay.
13) The dApp takes an hour to deploy into the network
14) Once this dApp is running it will show a default web page that looks like this:
 
Welcome to nginx!  
If you see this page, the nginx web server is successfully installed and working. Further configuration is required.  
  
For online documentation and support please refer to nginx.org.  
Commercial support is available at nginx.com.  
  
Thank you for using nginx.  

15) You can modify app_demo.sh to include the environment variables from step 5, the 'export' command is needed as shown
16) You can then run the script to contact each node and load a different web page
17) Reload the web page and you will see a page like this:

Flux Node Rank  
Node IP   
  
Queue Position	  
Time to Front  

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
