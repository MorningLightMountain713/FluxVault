from fluxvault.fluxkeeper import FluxKeeper

# Still need to make this async safe + add dispatcher. Makes it an easier interface so
# punters don't have to subclass FluxKeeper

# can hardcode the ips here or use app_name, if ips provided will use those over app name
flux_keeper = FluxKeeper(vault_dir="vault", comms_port=8888, agent_ips=["127.0.0.1"])

# Can show what methods are avaiable on the agents
print(flux_keeper.get_all_agents_methods())

flux_keeper.poll_all_agents()
