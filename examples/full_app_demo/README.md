## Full app demo

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

- Start the agent first (from the `agent` directory) `python agent.py`
- Start the keeper (from the `keeper` directory) `python keeper.py <Vanity string>`

## What is happening?

- Standard Agent is started
- Keeper checks into agent and is authenticated
- Keeper loads vanity_finder plugin to Agent. This gives the Agent extra functionality
- Agent then requests a file `runner.py`
- Keeper then sends command to run this file (this is extended functionality that the plugin provides)
- Agent installs any necessary packages
- Agent runs the file, which starts up processes (half of the available cpus)
- Each process starts iterating through addresses trying to find a match for the vanity string
- Keeper checks in every 30 seconds to see how they're getting on
- After 2:30, Keeper asks the Agent to stop work
- end
