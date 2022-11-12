import logging
import time
from typing import List, Optional

import daemon  # python-daemon package
import daemon.pidfile
import typer

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

    vault_log = logging.getLogger("fluxvault")
    aiotinyrpc_log = logging.getLogger("aiotinyrpc")
    level = logging.DEBUG if debug else logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    vault_log.setLevel(level)
    aiotinyrpc_log.setLevel(level)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler("keeper.log", mode="a")
    file_handler.setFormatter(formatter)

    vault_log.addHandler(stream_handler)
    aiotinyrpc_log.addHandler(stream_handler)

    if log_to_file:
        aiotinyrpc_log.addHandler(file_handler)
        vault_log.addHandler(file_handler)

    flux_keeper = FluxKeeper(
        vault_dir=vault_dir,
        comms_port=comms_port,
        app_name=app_name,
        agent_ips=agent_ip,
        log_to_file=log_to_file,
        debug=debug,
    )

    while True:
        flux_keeper.poll_all_agents()
        if run_once:
            break
        vault_log.info(f"sleeping {polling_interval} seconds...")
        time.sleep(polling_interval)


PREFIX = "FLUXVAULT"


def main(
    daemonize: bool = typer.Option(
        False, "--daemonize", "-d", envvar=f"{PREFIX}_DAEMONIZE"
    ),
    vault_dir: str = typer.Option(
        "vault", "--vault-dir", "-s", envvar=f"{PREFIX}_VAULT_DIR"
    ),
    comms_port: int = typer.Option(
        8888, "--comms-port", "-p", envvar=f"{PREFIX}_COMMS_PORT"
    ),
    app_name: str = typer.Option(None, "--app-name", "-a", envvar=f"{PREFIX}_APP_NAME"),
    log_to_file: bool = typer.Option(
        True, "--log-to-file", "-l", envvar=f"{PREFIX}_LOG_TO_FILE"
    ),
    debug: bool = typer.Option(False, "--debug", envvar=f"{PREFIX}_DEBUG"),
    polling_interval: int = typer.Option(
        300, "--polling-interval", "-i", envvar=f"{PREFIX}_POLLING_INTERVAL"
    ),
    run_once: bool = typer.Option(
        False, "--run-once", "-o", envvar=f"{PREFIX}_RUN_ONCE"
    ),
    agent_ip: Optional[List[str]] = typer.Option(None, envvar=f"{PREFIX}_AGENT_IP"),
):
    if daemonize and run_once:
        exit("\nIf daemonize set, run-once can't be set")

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
