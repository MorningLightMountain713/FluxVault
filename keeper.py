import daemon  # python-daemon package
import daemon.pidfile
import typer
import time
import logging

from typing import Optional, List

# Still need to make this async safe + add dispatcher. Makes it an easier interface so
# punters don't have to subclass FluxKeeper

# extensions = FluxVaultExtensions()


# @extensions.create
# def signCertificateCsr():
#     raise NotImplementedError


# @extensions.create
# def requestAgentGenerateCsr():
#     raise NotImplementedError


# remove appname - we can get this from socket.gethostbyname(), maybe add is_flux_node flag


# Can show what methods are avaiable on the agents
# print(flux_keeper.get_all_agents_methods())
# print(flux_keeper.get_all_agents_methods())

# flux_keeper.poll_all_agents()

# print(flux_keeper.agents["127.0.0.1"].extract_tar("/app/app.tar.gz", "/app"))
# flux_keeper.signCertificate()
# flux_keeper.run_agent_entrypoint()
# flux_keeper.extract_tar("newtar.tar.gz", "/Users/davew/code/flux/fluxvault/testdir")
# flux_keeper.poll_all_agents()


def run_keeper(
    vault_dir,
    comms_port,
    app_name,
    agent_ip,
    log_to_file,
    debug,
    polling_interval,
    run_once,
):
    from fluxvault import FluxKeeper

    vault_log = logging.getLogger("flux_vault")
    aiotinyrpc_log = logging.getLogger("aiotinyrpc")
    level = logging.DEBUG if debug else logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s: %(name)s: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    vault_log.setLevel(level)
    aiotinyrpc_log.setLevel(level)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler("keeper.log", mode="a")
    file_handler.setFormatter(formatter)

    vault_log.addHandler(stream_handler)
    aiotinyrpc_log.addHandler(stream_handler)

    flux_keeper = FluxKeeper(
        vault_dir=vault_dir,
        comms_port=comms_port,
        app_name=app_name,
        agent_ips=agent_ip,
        log_to_file=log_to_file,
        debug=debug,
    )

    # if log_to_file:
    #     aiotinyrpc_log.addHandler(file_handler)
    #     vault_log.addHandler(file_handler)

    while True:
        flux_keeper.poll_all_agents()
        if run_once:
            break
        vault_log.info(f"sleeping {polling_interval} seconds...")
        time.sleep(polling_interval)


def main(
    daemonize: bool = typer.Option(False, "--daemonize", "-d"),
    vault_dir: str = typer.Option("vault", "--vault-dir", "-s"),
    comms_port: int = typer.Option(8888, "--comms-port", "-p"),
    app_name: str = typer.Option(None, "--app-name", "-a"),
    log_to_file: bool = typer.Option(True, "--log-to-file", "-l"),
    debug: bool = typer.Option(False, "--debug"),
    polling_interval: int = typer.Option(300, "--polling-interval", "-i"),
    run_once: bool = typer.Option(False, "--run-once", "-o"),
    agent_ip: Optional[List[str]] = typer.Option(None),
):
    if daemonize and run_once:
        exit("If daemonize set, run-once can't be set")

    params = [
        vault_dir,
        comms_port,
        app_name,
        agent_ip,
        log_to_file,
        debug,
        polling_interval,
        run_once,
    ]

    if daemonize:
        with daemon.DaemonContext():
            run_keeper(*params)
    else:
        run_keeper(*params)


def entrypoint():
    typer.run(main)


if __name__ == "__main__":
    typer.run(main)
