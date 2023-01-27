import asyncio
import getpass
import logging
from pathlib import Path

import keyring
import typer
import yaml

from fluxvault import FluxAgent, FluxKeeper
from fluxvault.fluxapp_config import (
    FileSystemEntry,
    FluxAppConfig,
    FluxComponentConfig,
    FluxTask,
)
from fluxvault.helpers import SyncStrategy
from fluxvault.registrar import FluxAgentRegistrar, FluxPrimaryAgent

PREFIX = "FLUXVAULT"

app = typer.Typer(rich_markup_mode="rich", add_completion=False)
log = logging.getLogger("fluxvault")


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
    fluxrpc_log = logging.getLogger("fluxrpc")
    level = logging.DEBUG if debug else logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    vault_log.setLevel(level)
    fluxrpc_log.setLevel(level)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(logfile_path, mode="a")
    file_handler.setFormatter(formatter)

    vault_log.addHandler(stream_handler)
    fluxrpc_log.addHandler(stream_handler)
    if log_to_file:
        fluxrpc_log.addHandler(file_handler)
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


def get_signing_key(signing_address) -> str:
    signing_key = keyring.get_password("fluxvault_app", signing_address)

    if not signing_key:
        signing_key = getpass.getpass(
            f"\n{colours.OKGREEN}** WARNING **\n\nYou are about to enter your private key into a 3rd party application. Please make sure your are comfortable doing so. If you would like to review the code to make sure your key is safe... please visit https://github.com/RunOnFlux/FluxVault to validate the code.{colours.ENDC}\n\n Please enter your private key (in WIF format):\n"
        )
        store_key = yes_or_no(
            "Would you like to store your private key in your device's secure store?\n\n(macOS: keyring, Windows: Windows Credential Locker, Ubuntu: GNOME keyring.\n\n This means you won't need to enter your private key every time this program is run.",
        )
        if store_key:
            keyring.set_password("fluxvault_app", signing_address, signing_key)

    return signing_key


def build_app_from_cli(
    app_name,
    managed_objects,
    sign_connections,
    signing_address,
    agent_ips,
    run_once,
    polling_interval,
    comms_port,
) -> FluxAppConfig:
    if sign_connections:
        signing_address = get_signing_key()
        if not signing_address:
            raise ValueError(
                "signing_address must be provided if signing connections (keyring)"
            )

    app = FluxAppConfig(
        app_name,
        sign_connections=sign_connections,
        signing_key=signing_address,
        agent_ips=agent_ips,
        run_once=run_once,
        polling_interval=polling_interval,
        comms_port=comms_port,
    )

    common_objects = []
    for obj_str in managed_objects:
        parts = obj_str.split("@")

        component_name = ""
        if len(parts) > 1:
            component_name = parts[1]
            obj_str = parts[0]

        split_obj = obj_str.split(":")
        print("split", split_obj)
        local = Path(split_obj[0])

        sync_strat = None
        try:
            remote = Path(split_obj[1])
            print("remote", remote)
            # this will break on remote paths of S, A, or C"
            if str(remote) in ["S", "A", "C"]:
                # we don't have a remote, just a sync strat
                sync_strat = remote
                remote = local
        except IndexError:
            # we don't have a remote path
            remote = local
        print("strat", sync_strat)
        print("remote", remote)
        if not sync_strat:
            try:
                sync_strat = Path(split_obj[2])
            except IndexError:
                sync_strat = "S"

        match sync_strat:
            case "S":
                sync_strat = SyncStrategy.STRICT
            case "A":
                sync_strat = SyncStrategy.ALLOW_ADDS
            case "C":
                sync_strat = SyncStrategy.ENSURE_CREATED

        if local.name != str(local):
            log.error(f"Local file absolute path not allowed for: {local}... skipping")
            continue

        managed_object = FileSystemEntry(local, remote, sync_strategy=sync_strat)

        if not component_name:
            common_objects.append(managed_object)
            continue

        component = app.ensure_included(component_name)
        component.file_manager.add_object(managed_object)

    app.update_common_objects(common_objects)

    return app


def managed_objects_builder(files: list) -> list:
    managed_objects = []
    for file in files:
        local = Path(file.get("name", "."))
        remote = Path(file.get("remote_path", "."))
        sync_strategy = SyncStrategy[
            file.get("sync_strategy", SyncStrategy.STRICT.name)
        ]

        managed_object = FileSystemEntry(local, remote, sync_strategy=sync_strategy)
        managed_objects.append(managed_object)
    return managed_objects


# do this as a lambda?
# flux_tasks = []
# map(lambda x: flux_tasks.append(FluxTask(x.get("name"), x.get("params"))), tasks)
def tasks_builder(tasks: list) -> list:
    flux_tasks = []
    for task in tasks:
        flux_task = FluxTask(task.get("name"), task.get("params"))
        flux_tasks.append(flux_task)
    return flux_tasks


def build_apps_from_loadout_file(path: str) -> list:

    loadout_path = Path(path)
    apps = []

    if not loadout_path.exists():
        raise ValueError(f"Loadout path {loadout_path} doesn't exist")

    with open(str(loadout_path), "r") as stream:
        try:
            loadout = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            raise ValueError(f"loadout {loadout_path} is not parseable.\n\n{exc}")

    for app_name, params in loadout.get("apps").items():
        components = params.pop("components", [])
        # agent_ips = params.get("agent_ips")
        # polling_interval = params.get("polling_interval")
        common_objects = params.pop("managed_objects", [])
        app = FluxAppConfig(app_name, **params)
        app.file_manager.add_objects(managed_objects_builder(common_objects))

        for component_name, directives in components.items():
            component = FluxComponentConfig(component_name)
            for directive, items in directives.items():
                match directive:
                    case "working_dir":
                        component.working_dir = items
                    case "managed_objects":
                        component.file_manager.add_objects(
                            managed_objects_builder(items)
                        )
                    case "tasks":
                        component.add_tasks(tasks_builder(items))
            app.add_component(component)
        apps.append(app)
    return apps


@app.command()
def keeper(
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
    vault_dir: str = typer.Option(
        None,
        "--vault-dir",
        "-d",
        envvar=f"{PREFIX}_VAULT_DIR",
        show_envvar=False,
    ),
    loadout_path: str = typer.Option(
        None,
        "--loadout-path",
        "-l",
        envvar=f"{PREFIX}_LOADOUT_PATH",
        show_envvar=False,
    ),
    managed_objects: str = typer.Option(
        "",
        "--managed-objects",
        "-m",
        envvar=f"{PREFIX}_MANAGED_OBJECTS",
        show_envvar=False,
        help="""Comma seperated string of managed object paths.
        
        Local files must be a relative path (relative to vault_dir)
        Remote files can be relative (working_dir) or absolute
        
        If using local / remote files, file name must match

        Any remote directories will be created if they don't exist

        Example:

        --managed-files file1.py,file2.txt:/remote/path/file2.txt,file3.py:dir/file3.py
        """,
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
        help="Contact agents once and exit",
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
    signing_address: str = typer.Option(
        "",
        envvar=f"{PREFIX}_SIGNING_ADDRESS",
        show_envvar=False,
        help="This is used to associate private key in keychain",
    ),
    gui: bool = typer.Option(
        False,
        "--gui",
        "-g",
        envvar=f"{PREFIX}_GUI",
        show_envvar=False,
        hidden=True,
        help="Run local gui server",
    ),
):

    if not vault_dir:
        vault_dir = Path().home() / ".vault"

    agent_ips = agent_ips.split(",")
    agent_ips = list(filter(None, agent_ips))

    managed_objects = managed_objects.split(",")
    managed_objects = list(filter(None, managed_objects))

    apps_config = []

    # this ignores any other command line directive
    if loadout_path:
        configs = build_apps_from_loadout_file(loadout_path)
        apps_config.extend(configs)

    # configure single app via command line parameters, Must have managed_objects
    elif app_name:
        if not managed_objects:
            raise ValueError(
                "If running single app (if app_name is set) you must pass in managed-files via cli param, alternatively, try using a loadout"
            )
        config = build_app_from_cli(
            app_name,
            managed_objects,
            sign_connections,
            signing_address,
            agent_ips,
            run_once,
            polling_interval,
            comms_port,
        )
        apps_config.append(config)

    else:
        raise ValueError("Either app_name or loadout_path must be specified")
    # Make sure all params are getting passed into app config first (ports etc)

    flux_keeper = FluxKeeper(
        apps_config=apps_config,
        vault_dir=vault_dir,
        gui=gui,
    )

    async def main():
        await flux_keeper.manage_apps()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())


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
    primary_agent_port: int = typer.Option(
        "2080",
        "--primary-agent-port",
        envvar=f"{PREFIX}_PRIMARY_AGENT_PORT",
        show_envvar=False,
        hidden=True,
        help="Primary agent port",
    ),
):

    whitelisted_addresses = whitelisted_addresses.split(",")
    whitelisted_addresses = list(filter(None, whitelisted_addresses))

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
