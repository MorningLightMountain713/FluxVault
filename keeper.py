from aiotinyrpc.dispatch import RPCDispatcher

from fluxvault import FluxKeeper

# Still need to make this async safe + add dispatcher. Makes it an easier interface so
# punters don't have to subclass FluxKeeper

extensions = RPCDispatcher()


@extensions.create
def signCertificate():
    raise NotImplementedError


@extensions.create
def requestAgentGenerateCsr():
    raise NotImplementedError


# can hardcode the ips here or use app_name, if ips provided will use those over app name
flux_keeper = FluxKeeper(
    vault_dir="vault",
    comms_port=8888,
    agent_ips=["127.0.0.1"],
    extensions=extensions,
)

# Can show what methods are avaiable on the agents
# print(flux_keeper.get_all_agents_methods())
# print(flux_keeper.get_all_agents_methods())
print(flux_keeper.poll_all_agents())
print(flux_keeper.agents["127.0.0.1"].extract_tar("/app/app.tar.gz", "/app"))
# flux_keeper.signCertificate()
flux_keeper.run_agent_entrypoint()
# flux_keeper.extract_tar("newtar.tar.gz", "/Users/davew/code/flux/fluxvault/testdir")
# flux_keeper.poll_all_agents()
