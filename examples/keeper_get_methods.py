"""Example showing how to see what methods the agents have available"""

import json

from fluxvault import FluxKeeper, FluxVaultExtensions

extensions = FluxVaultExtensions()

# Can add additional methods to the keeper, if you so choose
@extensions.create
def signCertificateCsr():
    raise NotImplementedError


@extensions.create
def requestAgentGenerateCsr():
    raise NotImplementedError


keeper = FluxKeeper(
    extensions=extensions,
    vault_dir="examples/files",
    comms_port=8888,
    agent_ips=["127.0.0.1"],
)

methods = keeper.get_all_agents_methods()

print(json.dumps(methods, indent=2))
