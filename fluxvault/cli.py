import getpass
import logging
import time

import keyring
import typer

from fluxvault import FluxAgent, FluxKeeper
from fluxvault.registrar import FluxAgentRegistrar, FluxPrimaryAgent

PREFIX = "FLUXVAULT"

app = typer.Typer(rich_markup_mode="rich", add_completion=False)


class colours:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


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


def yes_or_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [yes/no] "
    elif default == "yes":
        prompt = f" [{colours.OKGREEN}Yes{colours.ENDC}] "
    elif default == "no":
        prompt = f" [{colours.OKGREEN}No{colours.ENDC}] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        print(question + prompt, end="")
        choice = input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")


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
        envvar=f"{PREFIX}_AGENT_IPS",
        show_envvar=False,
        help="If your not using app name to determine ips",
    ),
    sign_connections: bool = typer.Option(
        False,
        "--sign-connections",
        "-q",
        envvar=f"{PREFIX}_SIGN_CONNECTIONS",
        show_envvar=False,
        help="Whether or not to sign outbound connections",
    ),
    zelid: str = typer.Option(
        "",
        envvar=f"{PREFIX}_ZELID",
        show_envvar=False,
        help="This is used to associate private key in keychain",
    ),
):

    agent_ips = agent_ips.split(",")
    agent_ips = list(filter(None, agent_ips))

    if sign_connections:
        if not zelid:
            raise ValueError("zelid must be provided if signing connections (keyring)")

        signing_key = keyring.get_password("fluxvault_app", zelid)

        if not signing_key:
            signing_key = getpass.getpass(
                f"\n{colours.OKGREEN}** WARNING **\n\nYou are about to enter your private key into a 3rd party application. Please make sure your are comfortable doing so. If you would like to review the code to make sure your key is safe... please visit https://github.com/RunOnFlux/FluxVault to validate the code.{colours.ENDC}\n\n Please enter your private key (in WIF format):\n"
            )
            store_key = yes_or_no(
                "Would you like to store your private key in your device's secure store?\n\n(macOS: keyring, Windows: Windows Credential Locker, Ubuntu: GNOME keyring.\n\n This means you won't need to enter your private key every time this program is run.",
            )
            if store_key:
                keyring.set_password("fluxvault_app", zelid, signing_key)

    flux_keeper = FluxKeeper(
        vault_dir=vault_dir,
        comms_port=comms_port,
        app_name=app_name,
        agent_ips=agent_ips,
        sign_connections=sign_connections,
        signing_key=signing_key,
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
    enable_registrar: bool = typer.Option(
        False,
        "--registrar",
        "-s",
        envvar=f"{PREFIX}_REGISTRAR",
        show_envvar=False,
        help="Act as a proxy registrar for other agents",
    ),
    registrar_port: int = typer.Option(
        "2080",
        "--registrar-port",
        "-z",
        envvar=f"{PREFIX}_REGISTRAR_PORT",
        show_envvar=False,
        help="Port for registrar to listen on",
    ),
    registrar_address: str = typer.Option(
        "0.0.0.0",
        "--registrar-address",
        "-v",
        envvar=f"{PREFIX}_REGISTRAR_ADDRESS",
        show_envvar=False,
        help="Address for registrar to bind on",
    ),
    enable_registrar_fileserver: bool = typer.Option(
        False,
        "--registrar-fileserver",
        "-q",
        envvar=f"{PREFIX}_REGISTRAR_FILESERVER",
        show_envvar=False,
        help="Serve files over http (no authentication)",
    ),
    managed_files: str = typer.Option(
        "",
        "--manage-files",
        "-m",
        envvar=f"{PREFIX}_MANAGED_FILES",
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
    whitelisted_addresses: str = typer.Option(
        "",
        "--whitelist-addresses",
        "-w",
        envvar=f"{PREFIX}_WHITELISTED_ADDRESSES",
        show_envvar=False,
        help="Comma seperated addresses to whitelist",
    ),
    verify_source_address: bool = typer.Option(
        False,
        "--verify-source-address",
        "-z",
        envvar=f"{PREFIX}_VERIFY_SOURCE_ADDRESS",
        show_envvar=False,
        help="Matches source ip to your whitelist",
    ),
    signed_vault_connections: bool = typer.Option(
        False,
        "--signed-vault-connections",
        "-k",
        envvar=f"{PREFIX}_SIGNED_VAULT_CONNECTIONS",
        show_envvar=False,
        help="Expects all keeper connections to be signed",
    ),
    zelid: str = typer.Option(
        "",
        envvar=f"{PREFIX}_ZELID",
        show_envvar=False,
        help="Testing only... if you aren't running this on a Fluxnode",
    ),
    subordinate: bool = typer.Option(
        False,
        "--subordinate",
        envvar=f"{PREFIX}_SUBORDINATE",
        show_envvar=False,
        hidden=True,
        help="If this agent is a subordinate of another agent",
    ),
    primary_agent_name: str = typer.Option(
        "fluxagent",
        "--primary-agent-name",
        envvar=f"{PREFIX}_PRIMARY_AGENT_NAME",
        show_envvar=False,
        help="Primary agent name",
    ),
    primary_agent_address: str = typer.Option(
        "",
        "--primary-agent-address",
        envvar=f"{PREFIX}_PRIMARY_AGENT_ADDRESS",
        show_envvar=False,
        hidden=True,
        help="Primary agent address",
    ),
    primary_agent_port: str = typer.Option(
        "",
        "--primary-agent-port",
        envvar=f"{PREFIX}_PRIMARY_AGENT_PORT",
        show_envvar=False,
        hidden=True,
        help="Primary agent port",
    ),
):

    whitelisted_addresses = whitelisted_addresses.split(",")
    whitelisted_addresses = list(filter(None, whitelisted_addresses))
    managed_files = managed_files.split(",")
    managed_files = list(filter(None, managed_files))

    registrar = None
    if enable_registrar:
        registrar = FluxAgentRegistrar(
            bind_address=registrar_address,
            bind_port=registrar_port,
            enable_fileserver=enable_registrar_fileserver,
        )

    primary_agent = None
    if subordinate:
        primary_agent = FluxPrimaryAgent(
            name=primary_agent_name,
            address=primary_agent_address,
            port=primary_agent_port,
        )

    agent = FluxAgent(
        bind_address=bind_address,
        bind_port=bind_port,
        enable_registrar=enable_registrar,
        registrar=registrar,
        primary_agent=primary_agent,
        managed_files=managed_files,
        working_dir=working_dir,
        whitelisted_addresses=whitelisted_addresses,
        verify_source_address=verify_source_address,
        signed_vault_connections=signed_vault_connections,
        zelid=zelid,
        subordinate=subordinate,
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


@app.command()
def remove_private_key(zelid: str):
    try:
        keyring.delete_password("fluxvault_app", zelid)
    except keyring.errors.PasswordDeleteError:
        typer.echo("Private key doesn't exist")
    else:
        typer.echo("Private key deleted")


def entrypoint():
    """Called by console script"""
    app()


if __name__ == "__main__":
    app()
