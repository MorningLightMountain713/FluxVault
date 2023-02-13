import asyncio
import getpass
import logging
from pathlib import Path

import keyring
# import pandas
import typer
import yaml
# from tabulate import tabulate

from fluxvault import FluxAgent, FluxKeeper
from fluxvault.fluxapp import FluxApp, FluxComponent, FluxTask, RemoteStateDirective
from fluxvault.helpers import SyncStrategy
from fluxvault.registrar import FluxAgentRegistrar, FluxPrimaryAgent

PREFIX = "FLUXVAULT"

app = typer.Typer(rich_markup_mode="rich", add_completion=False)
keeper = typer.Typer(rich_markup_mode="rich", add_completion=False)
# agent =  typer.Typer(rich_markup_mode="rich", add_completion=False)

app.add_typer(keeper, name="keeper")
# app.add_typer(agent)

from fluxvault.log import log


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
    state_directives,
    signing_address,
    agent_ips,
    run_once,
    polling_interval,
    comms_port,
    remote_workdirs,
) -> FluxApp:

    app = FluxApp(
        app_name,
        sign_connections=sign_connections,
        signing_key=signing_address,
        agent_ips=agent_ips,
        run_once=run_once,
        polling_interval=polling_interval,
        comms_port=comms_port,
    )

    # THIS IS BROKEN RIGHT NOW

    # /tmp/blah
    # component1:/tmp/blah,component2:/tmp/crag,default:/tmp
    # remote_workdirs = remote_workdirs.split(",")

    common_objects = []
    for obj_str in state_directives:
        parts = obj_str.split("@")

        component_name = ""
        if len(parts) > 1:
            component_name = parts[1]
            obj_str = parts[0]

        split_obj = obj_str.split(":")
        local = Path(split_obj[0])

        sync_strat = None
        try:
            remote = Path(split_obj[1])
            # this will break on remote paths of S, A, or C"
            if str(remote) in ["S", "A", "C"]:
                # we don't have a remote, just a sync strat
                sync_strat = remote
                remote = None
        except IndexError:
            # we don't have a remote path
            remote = None
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

        if local.is_absolute():
            log.error(f"Local file absolute path not allowed for: {local}... skipping")
            continue

        # state_directive = RemoteStateDirective(
        #      local_path=local,
        #      sync_strategy=sync_strat,
        #      workdir
        #      prefix
        # )
    #     managed_object = AbstractFsEntry(
    #         local_path=local,
    #         fake_root=False,
    #         remote_prefix=remote,
    #         sync_strategy=sync_strat,
    #     )

    #     if not component_name:
    #         common_objects.append(managed_object)
    #         continue

    #     component = app.ensure_included(component_name)
    #     component.state_manager.add_object(managed_object)

    # app.update_common_objects(common_objects)

    # return app


@keeper.command()
def list_apps(
    vault_dir: str = typer.Option(
        None,
        "--vault-dir",
        "-d",
        envvar=f"{PREFIX}_VAULT_DIR",
        show_envvar=False,
    )
):

    if not vault_dir:
        vault_dir = Path().home() / ".vault"

    dfs = []
    for app_dir in vault_dir.iterdir():
        if not app_dir.is_dir():
            continue

        with open(app_dir / "config.yaml", "r") as stream:
            # pop elements so we don't write jumk
        #     config = yaml.safe_load(stream)
        #     for app_name, directives in config.items():
        #         components = directives.pop("components")
        #         df = pandas.json_normalize(components)
        #         print(df)

        # dfs.append(df)

    # table = tabulate(dfs, headers="keys", tablefmt="psql", showindex=False)
    # typer.echo(table)


@keeper.command()
def add_apps_via_loadout_file(
    loadout_path: str = typer.Argument(
        default=None,
        envvar=f"{PREFIX}_LOADOUT_PATH",
        show_envvar=False,
    )
):
    try:
        with open(loadout_path, "r") as stream:
            try:
                config: dict = yaml.safe_load(stream)
            except yaml.YAMLError as e:
                raise ValueError(
                    f"Error parsing vault config file: {loadout_path}. Exc: {e}"
                )
    except (FileNotFoundError, PermissionError) as e:
        raise ValueError(f"Error opening config file {loadout_path}. Exc: {e}")

    global_defaults = {
        "vault_dir": str(Path().home() / ".vault"),
        "remote_workdir": "/tmp",
        "sign_connections": False,
    }

    apps: dict = config.pop("apps")
    # merge all config in here up front.
    # global -> app level -> component level
    for app_name, directives in apps.items():
        app_directives: dict = global_defaults | directives

        if groups := app_directives.get("groups"):
            for group_name, group in groups.items():
                if directives := group.get("state_directives", None):
                    for d in directives:
                        if d.get("content_source"):
                            d[
                                "content_source"
                            ] = f"groups/{group_name}/{d['content_source']}"

        # only used at app level
        vault_dir = app_directives.pop("vault_dir")

        app_dir = Path(vault_dir) / Path(app_name)
        groups_dir = app_dir / "groups"
        components_dir = app_dir / "components"

        app_dir.mkdir(parents=True, exist_ok=True)
        groups_dir.mkdir(parents=True, exist_ok=True)
        components_dir.mkdir(parents=True, exist_ok=True)

        components: dict = app_directives.pop("components")
        for component_directives in components.values():
            if not component_directives.get("remote_workdir"):
                component_directives["remote_workdir"] = app_directives.get(
                    "remote_workdir"
                )

            if groups := component_directives.get("member_of"):
                groups.append("all")
            else:
                component_directives["member_of"] = ["all"]

        app_directives.pop("remote_workdir")
        log.info(f"New config dir: {app_dir / 'config.yaml'}")
        with open(app_dir / "config.yaml", "w") as stream:
            # allowed_config_keys = [
            #     "comms_port",
            #     "agent_ips",
            #     "state_directives",
            #     "components",
            # ]
            # config = {k: directives[k] for k in allowed_config_keys}
            stream.write(
                yaml.dump({"app_config": app_directives, "components": components})
            )


@keeper.command()
def add_app_via_cli(
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
    state_directives: str = typer.Option(
        "",
        "--state_directives",
        "-m",
        envvar=f"{PREFIX}_STATE_DIRECTIVES",
        show_envvar=False,
        help="""Comma seperated string of state directives.
        
        Update this""",
    ),
    remote_workdirs: str = typer.Option(
        None,
        "--remote-workdirs",
        "-l",
        envvar=f"{PREFIX}_REMOTE_WORKDIRS",
        show_envvar=False,
    ),
    signing_address: str = typer.Option(
        "",
        envvar=f"{PREFIX}_SIGNING_ADDRESS",
        show_envvar=False,
        help="This is used to associate private key in keychain",
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
):

    if not vault_dir:
        vault_dir = Path().home() / ".vault"

    if sign_connections:
        signing_address = get_signing_key()
        if not signing_address:
            raise ValueError(
                "signing_address must be provided if signing connections (keyring)"
            )

    agent_ips = agent_ips.split(",")
    agent_ips = list(filter(None, agent_ips))

    state_directives = state_directives.split(",")
    state_directives = list(filter(None, state_directives))

    apps = []

    # configure single app via command line parameters, Must have state_directives

    # config = build_app_from_cli(
    #     app_name,
    #     state_directives,
    #     signing_address,
    #     comms_port,
    #     remote_workdirs,
    # )
    # apps.append(config)

    # WRITE APPS TO DISK


@keeper.command()
def run(
    # Just disabling this for a while to focus on filesystem stuff
    # gui: bool = typer.Option(
    #     False,
    #     "--gui",
    #     "-g",
    #     envvar=f"{PREFIX}_GUI",
    #     show_envvar=False,
    #     hidden=True,
    #     help="Run local gui server",
    # ),
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
):
    # this takes app name, and any runtime stuff and sparks up app.
    # reads config from directives folder based on app.

    flux_keeper = FluxKeeper(
        # gui=gui,
    )

    async def main():
        await flux_keeper.manage_apps(run_once, polling_interval)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except Exception as e:
        log.error(repr(e))
    finally:
        flux_keeper.cleanup()


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
    # configure_logs(enable_logfile, logfile_path, debug)
    ...


@keeper.command()
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
