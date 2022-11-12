import typer

import time

import logging

from fluxvault import FluxKeeper, FluxAgent


PREFIX = "FLUXVAULT"

app = typer.Typer(rich_markup_mode="rich", add_completion=False)


def configure_logs(log_to_file, logfile_path, debug):
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
    file_handler = logging.FileHandler(logfile_path, mode="a")
    file_handler.setFormatter(formatter)

    vault_log.addHandler(stream_handler)
    aiotinyrpc_log.addHandler(stream_handler)
    if log_to_file:
        aiotinyrpc_log.addHandler(file_handler)
        vault_log.addHandler(file_handler)


@app.command()
def keeper(
    vault_dir: str = typer.Option(
        "vault",
        "--vault-dir",
        "-s",
        envvar=f"{PREFIX}_VAULT_DIR",
        show_envvar=False,
    ),
    comms_port: int = typer.Option(
        8888,
        "--comms-port",
        "-p",
        envvar=f"{PREFIX}_COMMS_PORT",
        show_envvar=False,
    ),
    app_name: str = typer.Option(
        None,
        "--app-name",
        "-a",
        envvar=f"{PREFIX}_APP_NAME",
        show_envvar=False,
    ),
    polling_interval: int = typer.Option(
        300,
        "--polling-interval",
        "-i",
        envvar=f"{PREFIX}_POLLING_INTERVAL",
        show_envvar=False,
    ),
    run_once: bool = typer.Option(
        False,
        "--run-once",
        "-o",
        envvar=f"{PREFIX}_RUN_ONCE",
        show_envvar=False,
        help="Contact agents once and bail",
    ),
    agent_ips: str = typer.Option(
        "",
        envvar=f"{PREFIX}_AGENT_IP",
        show_envvar=False,
    ),
):

    agent_ips = agent_ips.split(",")
    agent_ips = list(filter(None, agent_ips))

    flux_keeper = FluxKeeper(
        vault_dir=vault_dir,
        comms_port=comms_port,
        app_name=app_name,
        agent_ips=agent_ips,
    )

    log = logging.getLogger("fluxvault")

    while True:
        flux_keeper.poll_all_agents()
        if run_once:
            break
        log.info(f"sleeping {polling_interval} seconds...")
        time.sleep(polling_interval)


@app.command()
def agent(
    bind_address: str = typer.Option(
        "0.0.0.0",
        "--bind-address",
        "-b",
        envvar=f"{PREFIX}_BIND_ADDRESS",
        show_envvar=False,
    ),
    bind_port: int = typer.Option(
        8888,
        "--bind-port",
        "-p",
        envvar=f"{PREFIX}_BIND_PORT",
        show_envvar=False,
    ),
    enable_local_fileserver: bool = typer.Option(
        False,
        "--fileserver",
        "-s",
        envvar=f"{PREFIX}_FILESERVER",
        show_envvar=False,
        help="Serve vault files to other components",
    ),
    local_fileserver_port: int = typer.Option(
        "2080",
        "--fileserver-port",
        "-z",
        envvar=f"{PREFIX}_FILESERVER_PORT",
        show_envvar=False,
        help="For multi-component apps",
    ),
    manage_files: str = typer.Option(
        "",
        "--manage-files",
        "-m",
        envvar=f"{PREFIX}_MANAGE_FILES",
        show_envvar=False,
        help="Comma seperated files we want from keeper",
    ),
    working_dir: str = typer.Option(
        "/tmp",
        "--working-dir",
        "-i",
        envvar=f"{PREFIX}_WORKING_DIR",
        show_envvar=False,
        help="Where files will be stored",
    ),
    whitelist_addresses: str = typer.Option(
        "",
        "--whitelist-addresses",
        "-w",
        envvar=f"{PREFIX}_WHITELIST_ADDRESSES",
        show_envvar=False,
        help="Comma seperated addresses to whitelist",
    ),
    disable_authentication: bool = typer.Option(
        False,
        "--disable-authentication",
        "-a",
        envvar=f"{PREFIX}_DISABLE_AUTHENTICATION",
        show_envvar=False,
        help="Are you sure you want to do this?",
    ),
):

    whitelist_addresses = whitelist_addresses.split(",")
    whitelist_addresses = list(filter(None, whitelist_addresses))
    manage_files = manage_files.split(",")
    manage_files = list(filter(None, manage_files))

    params = [
        bind_address,
        bind_port,
        enable_local_fileserver,
        local_fileserver_port,
        manage_files,
        working_dir,
        whitelist_addresses,
        disable_authentication,
    ]

    agent = FluxAgent(
        bind_address=bind_address,
        bind_port=bind_port,
        enable_local_fileserver=enable_local_fileserver,
        local_fileserver_port=local_fileserver_port,
        managed_files=manage_files,
        working_dir=working_dir,
        whitelisted_addresses=whitelist_addresses,
        authenticate_vault=not disable_authentication,
    )

    agent.run()


@app.callback()
def main(
    debug: bool = typer.Option(
        False,
        "--debug",
        envvar=f"{PREFIX}_DEBUG",
        show_envvar=False,
        help="Enable extra debug logging",
    ),
    enable_logfile: bool = typer.Option(
        False,
        "--log-to-file",
        "-l",
        envvar=f"{PREFIX}_ENABLE_LOGFILE",
        show_envvar=False,
        help="Turn on logging to file",
    ),
    logfile_path: str = typer.Option(
        "/tmp/fluxvault.log",
        "--logfile-path",
        "-p",
        envvar=f"{PREFIX}_LOGFILE_PATH",
        show_envvar=False,
    ),
):
    configure_logs(enable_logfile, logfile_path, debug)


def entrypoint():
    app()


if __name__ == "__main__":
    app()
