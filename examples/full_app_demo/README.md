## Full app demo

** UNTESTED ON WINDOWS, MAY NOT WORK **

A contrived HD Wallet vanity finder demo using Keeper plugins.

Shows how extend both the Agent and the Keeper to meet your needs. Obviously, being written in Python, it is incredibly slow and only shown as an example of what can be done. 

It is assumed that fluxvault is already installed.

## How to use

Pick your vanity string to search addresses for. These are base58 strings so only the following characters are allowed:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

An example could be: `Pip`

Note, as the string gets longer, it gets exponentially harder to find.

- Start the agent first `fluxvault agent --bind-address 127.0.0.1 --signed-vault-connections --zelid 1GKugrE8cmw9NysWFJPwszBbETRLwLaLmM`

* Note - by default the agent working_dir is `/tmp` on unix and `C:\TEMP` on windows - once the keeper has run, this is where the agent files will be stored (unless you specify a working dir manually)

- Start the keeper (from the `keeper` directory) `python keeper.py <Vanity string>`

- Watch the magic happen

## What is happening?

- Standard Agent is started
- Keeper checks into agent and is authenticated
- Keeper sends plugin "vanity_finder" and file called runner.py
- Keeper loads vanity_finder plugin into Agent. This gives the Agent extra functionality
- Keeper then sends command to run `runner.py` file (this is extended functionality that the plugin provides)
- Agent installs any necessary packages
- Agent runs the file, which starts up processes (half of the available cpus)
- Each process starts iterating through addresses trying to find a match for the vanity string
- Keeper checks in every 30 seconds to see how they're getting on
- After 2:30, Keeper asks the Agent to stop work
- end
