import asyncio
import getpass
import hashlib
import logging
import sqlite3
import traceback
from enum import Enum
from pathlib import Path
from typing import Optional

import keyring
import pandas
import typer
import yaml
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from Cryptodome.Random import get_random_bytes
from tabulate import tabulate

from fluxvault import FluxAgent, FluxKeeper
from fluxvault.constants import WWW_ROOT
from fluxvault.fluxapp import FluxApp, FluxComponent, FluxTask, RemoteStateDirective
from fluxvault.fs import FsEntryStateManager
from fluxvault.helpers import AppMode, SyncStrategy
from fluxvault.registrar import FluxAgentRegistrar, FluxPrimaryAgent


# typer is stupid about enums so have to make our own here and convert
class LocalAppMode(str, Enum):
    FILESERVER = "FILESERVER"
    SINGLE_COMPONENT = "SINGLE_COMPONENT"
    MULTI_COMPONENT = "MULTI_COMPONENT"


PREFIX = "FLUXVAULT"

app = typer.Typer(rich_markup_mode="rich", add_completion=False)
keeper = typer.Typer(rich_markup_mode="rich", add_completion=False)
# agent =  typer.Typer(rich_markup_mode="rich", add_completion=False)
keys = typer.Typer(
    rich_markup_mode="rich", add_completion=False, help="Private key operations"
)
config = typer.Typer(
    rich_markup_mode="rich", add_completion=False, help="Configure apps"
)

app.add_typer(keeper, name="keeper")
# app.add_typer(agent)
keeper.add_typer(keys, name="keys")
keeper.add_typer(config, name="config")

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


# def configure_logs(log_to_file, logfile_path, debug):
#     vault_log = logging.getLogger("fluxvault")
#     fluxrpc_log = logging.getLogger("fluxrpc")
#     level = logging.DEBUG if debug else logging.INFO

#     formatter = logging.Formatter(
#         "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
#     )

#     vault_log.Level(level)
#     fluxrpc_log.setLevel(level)

#     stream_handler = logging.StreamHandler()
#     stream_handler.setFormatter(formatter)
#     file_handler = logging.FileHandler(logfile_path, mode="a")
#     file_handler.setFormatter(formatter)

#     vault_log.addHandler(stream_handler)
#     fluxrpc_log.addHandler(stream_handler)
#     if log_to_file:
#         fluxrpc_log.addHandler(file_handler)
#         vault_log.addHandler(file_handler)


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


def fetch_and_store_signing_key(signing_address: str, signing_key: str = "") -> str:
    store_key = True

    if not signing_key:
        signing_key = keyring.get_password("fluxvault_app", signing_address)

    if not signing_key:
        signing_key = getpass.getpass(
            f"\n{colours.OKGREEN}** WARNING **\n\nYou are about to enter your private key into a 3rd party application. Please make sure your are comfortable doing so. If you would like to review the code to make sure your key is safe... please visit https://github.com/RunOnFlux/FluxVault to validate the code.{colours.ENDC}\n\n Please enter your private key (in WIF format):\n"
        )
        store_key = yes_or_no(
            "Would you like to store your private key in your device's secure store?\n\n(macOS: keyring, Windows: Windows Credential Locker, Ubuntu: GNOME keyring.\n\n This means you won't need to enter your private key every time this program is run.",
        )
    if store_key:
        print(type(signing_address))
        print(type(signing_key))
        keyring.set_password("fluxvault_app", signing_address, signing_key)

    return signing_key


@keys.command(help="Dump all addresses for stored private keys")
def show_all():
    root = FluxKeeper.setup()
    db_dir = root / "db"
    con = sqlite3.connect(db_dir / "fluxvault.db")
    cur = con.cursor()

    with con:
        data = cur.execute("SELECT * FROM STORED_KEYS")

    print()
    print(tabulate(data, headers="keys", tablefmt="psql"))


@keys.command(help="Create a new signing key")
def create():
    h = hashlib.sha256(get_random_bytes(64)).digest()
    seckey = CBitcoinSecret.from_secret_bytes(h)
    address = P2PKHBitcoinAddress.from_pubkey(seckey.pub)

    root = FluxKeeper.setup()
    db_dir = root / "db"

    if fetch_and_store_signing_key(str(address), str(seckey)):
        con = sqlite3.connect(db_dir / "fluxvault.db")
        cur = con.cursor()

        with con:
            cur.execute(f"INSERT into STORED_KEYS (address) VALUES ('{address}')")
        print(f"Private key stored. Address to use on Agent: {address}")


@keys.command(help="Add signing key to your devices secure storage")
def add(
    signing_address: str = typer.Argument(
        ...,
        envvar=f"{PREFIX}_SIGNING_ADDRESS",
        show_envvar=False,
        help="The address you would like to use for signing messages",
    )
):
    root = FluxKeeper.setup()
    db_dir = root / "db"
    if fetch_and_store_signing_key(signing_address):
        con = sqlite3.connect(db_dir / "fluxvault.db")
        cur = con.cursor()

        with con:
            cur.execute(
                f"INSERT into STORED_KEYS (address) VALUES ('{signing_address}')"
            )


@config.command(help="List all apps that are available to run")
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
        vault_dir: Path = Path().home() / ".vault"

    data = []

    for app_dir in vault_dir.iterdir():
        if not app_dir.is_dir():
            continue
        app_name = app_dir.name
        with open(app_dir / "config.yaml", "r") as stream:
            config = yaml.safe_load(stream)
            base = config["app_config"]
            comms_port = base["comms_port"]
            ips = base.get("fluxnode_ips", [])
            sign_connections = base["sign_connections"]
            component_count = len(config.get("components", []))
            data.append([app_name, comms_port, ips, sign_connections, component_count])

    df = pandas.DataFrame(
        data,
        columns=[
            "App Name",
            "Comms Port",
            "Fluxnode Ips",
            "Sign Connections",
            "Components",
        ],
    )
    print()
    print(
        tabulate(
            df,
            headers="keys",
            tablefmt="psql",
            showindex=False,
        )
    )


@config.command(
    help="""Load new apps into config, use `run` method to run them

                Example:

                apps:
                    gravyboat:
                        # vault_dir: /Users/bob/custom_vaultdir
                        remote_workdir: /tmp/gravyboat
                        fluxnode_ips: [172.26.26.126]
                        comms_port: 8888
                        groups:
                        # all components are automatically a member of this group
                        all:
                            state_directives:
                            # this is saying where the actual file is located
                            - content_source: chud.txt
                                # this remote path is absolute, so the final path on the agent will be /tmp/chudder/chud.txt
                                remote_dir: /tmp/chudder
                        # this is a custom group
                        seagulls:
                            state_directives:
                            - content_source: crankyseagull
                                remote_dir: /tmp/jumbo
                        components:
                        127.0.0.1: # this would normally be a friendly component name, but on my test machine, just using ip
                            # these are specific to a component
                            remote_workdir: /tmp/127
                            state_directives:
                            - name: blah.txt
                                # this remote path is relative, so the final path on the agent will be /tmp/127/blah/blah.txt
                                remote_dir: blah
                        fluxagent: # this is a component name
                            # this component will receive objects from the  `seagulls` group
                            member_of: [seagulls]
                            state_directives:
                            - content_source: blah.txt
                                # this file gets crc checked and replaced if different
                                sync_strategy: STRICT
                                # if content_source isn't used, fluxvault will look in the component staging_dir to see if an
                                # objects name matches. This could potentially be problematic, if it doubt, use content_source. Name / remote dir
                                # is more for if you put your objects directly in fake_root.
                            - name: salami
                                remote_dir: /tmp/jumbo
                                sync_strategy: STRICT"""
)
def add_apps_via_loadout_file(
    loadout_path: str = typer.Argument(
        ...,
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


@keeper.command(help="Run app based on CLI parameters only")
def run_single_app(
    app_name: str = typer.Argument(
        ...,
        envvar=f"{PREFIX}_APP_NAME",
        show_envvar=False,
        show_default=False,
    ),
    components: Optional[str] = typer.Argument(
        None,
        envvar=f"{PREFIX}_COMPONENTS",
        show_envvar=False,
        show_default=False,
        help="comma seperated list of component names",
    ),
    app_mode: LocalAppMode = typer.Option(
        LocalAppMode.FILESERVER,
        "-m",
        "--app-mode",
        envvar=f"{PREFIX}_APP_NAME",
        show_envvar=False,
        show_default=False,
    ),
    fileserver_dir: Path = typer.Option(
        Path().resolve(),
        "-f",
        "--fileserver-dir",
        envvar=f"{PREFIX})_FILESERVER_DIR",
        show_envvar=False,
        show_default=False,
    ),
    comms_port: int = typer.Option(
        8888,
        "--comms-port",
        "-p",
        envvar=f"{PREFIX}_COMMS_PORT",
        show_envvar=False,
    ),
    vault_dir: str = typer.Option(
        Path().home() / ".vault",
        "--vault-dir",
        "-d",
        envvar=f"{PREFIX}_VAULT_DIR",
        show_envvar=False,
    ),
    state_directives: str = typer.Option(
        "",
        "--state-directives",
        "-s",
        envvar=f"{PREFIX}_STATE_DIRECTIVES",
        show_envvar=False,
        help="""Comma seperated string of state directives.

        Format for state-directive  <local-path>:<remote-path-prefix>:<sync-strat>@<component>

        SYNC_STRAT: S = STRICT, C = ENSURE_CREATED, A = ALLOW_ADDS

        For example: blah.txt:/tmp/myfiles:S@fluxagent""",
    ),
    remote_workdir: str = typer.Option(
        Path("/tmp"),
        "--remote-workdir",
        "-r",
        envvar=f"{PREFIX}_REMOTE_WORKDIR",
        show_envvar=False,
    ),
    # signing_address: str = typer.Option(
    #     "",
    #     envvar=f"{PREFIX}_SIGNING_ADDRESS",
    #     show_envvar=False,
    #     help="This is used to associate private key in keychain",
    # ),
    agent_ips: str = typer.Option(
        "",
        envvar=f"{PREFIX}_AGENT_IPS",
        show_envvar=False,
        help="If your not using app name to determine ips",
    ),
    # sign_connections: bool = typer.Option(
    #     False,
    #     "--sign-connections",
    #     "-q",
    #     envvar=f"{PREFIX}_SIGN_CONNECTIONS",
    #     show_envvar=False,
    #     help="Whether or not to sign outbound connections",
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

    if not components and app_mode != LocalAppMode.FILESERVER:
        raise ValueError(
            "You must specify components if not running in Fileserver mode"
        )

    # if sign_connections:
    #     signing_address = get_signing_key()
    #     if not signing_address:
    #         raise ValueError(
    #             "signing_address must be provided if signing connections (keyring)"
    #         )

    agent_ips = agent_ips.split(",")
    agent_ips = list(filter(None, agent_ips))

    state_directives = state_directives.split(",")
    state_directives = list(filter(None, state_directives))

    app_config = {}
    components_config = {}

    # typer sucks with enums
    app_mode_map = {
        "FILESERVER": AppMode.FILESERVER,
        "SINGLE_COMPONENT": AppMode.SINGLE_COMPONENT,
        "MULTI_COMPONENT": AppMode.MULTI_COMPONENT,
    }

    app_config["comms_port"] = comms_port
    # app_config["sign_connections"] = sign_connections
    # app_config["signing_key"] = signing_address
    app_config["fluxnode_ips"] = agent_ips
    app_config["groups"] = {"all": {"state_directives": []}}
    app_config["app_mode"] = app_mode_map[app_mode.value]
    app_config["fileserver_dir"] = fileserver_dir

    if components:
        components = list(filter(None, components.split(",")))
    else:
        # we are running as fileserver
        components = ["FILESERVER"]
        remote_workdir = WWW_ROOT

    for component_str in components:
        groups = ["all"]
        component_items = list(filter(None, component_str.split(":")))
        if len(component_items) > 1:
            component_name = component_items.pop(0)
            groups.extend(component_items)
        else:
            component_name = component_items[0]

        components_config[component_name] = {
            "member_of": groups,
            "remote_workdir": remote_workdir,
            "state_directives": [],
        }

    for obj_str in state_directives:
        parts = obj_str.split("@")

        component_name = None
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
                sync_strat = split_obj[2]
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

        if not component_name:
            source = "groups/all" / local
        else:
            source = Path("components") / component_name / "staging" / local

        directive = {
            "content_source": source,
            "remote_dir": remote,
            "sync_strategy": sync_strat.name,
        }

        if not component_name:
            app_config["groups"]["all"]["state_directives"].append(directive)
        else:
            components_config[component_name]["state_directives"].append(directive)

    # if app_mode == LocalAppMode.FILESERVER:
    #     if fileserver_dir.is_dir():

    #     root_dir = Path(vault_dir).resolve()
    # else:

    root_dir = Path(vault_dir) / app_name

    config = {"app_config": app_config, "components": components_config}

    app = FluxKeeper.build_app(app_name, root_dir, config)

    flux_keeper = FluxKeeper(
        # gui=gui,
        app=app
    )

    async def main():
        await flux_keeper.manage_apps(run_once, polling_interval)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except Exception as e:
        print("Error closing down !!!")
        traceback.print_exc()
    finally:
        flux_keeper.cleanup()


@keeper.command(help="Run keeper; loads all apps from vault dir")
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
    vault_dir: str = typer.Option(
        Path().home() / ".vault",
        "--vault-dir",
        "-d",
        envvar=f"{PREFIX}_VAULT_DIR",
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
        help="Contact agents once and exit",
    ),
):
    # this takes app name, and any runtime stuff and sparks up the app.
    # reads config from directives folder based on app.

    flux_keeper = FluxKeeper(
        # gui=gui,
        vault_dir=vault_dir,
    )

    async def main():
        await flux_keeper.manage_apps(run_once, polling_interval)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except Exception as e:
        print(f"Error closing: {repr(e)}")
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
    # enable_registrar: bool = typer.Option(
    #     False,
    #     "--registrar",
    #     "-s",
    #     envvar=f"{PREFIX}_REGISTRAR",
    #     show_envvar=False,
    #     help="Act as a proxy registrar for other agents",
    # ),
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
    enable_fileserver: bool = typer.Option(
        False,
        "--fileserver",
        "-q",
        envvar=f"{PREFIX}_FILESERVER",
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
    auth_id: str = typer.Option(
        "",
        envvar=f"{PREFIX}_AUTH_ID",
        show_envvar=False,
        help="If you're using an auth address other than your zelid",
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

    registrar = FluxAgentRegistrar(
        bind_address=registrar_address,
        bind_port=registrar_port,
        enable_fileserver=enable_fileserver,
        working_dir=WWW_ROOT,
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
        registrar=registrar,
        primary_agent=primary_agent,
        whitelisted_addresses=whitelisted_addresses,
        verify_source_address=verify_source_address,
        signed_vault_connections=signed_vault_connections,
        auth_id=auth_id,
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


@keys.command(help="Delete specified private key from keyring")
def remove(address: str):
    try:
        keyring.delete_password("fluxvault_app", address)
    except keyring.errors.PasswordDeleteError:
        typer.echo("Private key already deleted")
    else:
        typer.echo("Private key deleted")
    finally:
        root = FluxKeeper.setup()
        db_dir = root / "db"
        con = sqlite3.connect(db_dir / "fluxvault.db")
        cur = con.cursor()

        with con:
            cur.execute(f"DELETE FROM STORED_KEYS WHERE address = '{address}'")


def entrypoint():
    """Called by console script"""
    app()


if __name__ == "__main__":
    app()
