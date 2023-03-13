import os

import sqlite3
import sys
from pathlib import Path

# from showinfm import show_in_file_manager


def app_dir():
    r"""
    Get OS specific data directory path for fluxvault.
    Typical user data directories are:
        macOS:    ~/Library/Application Support/
        Unix:     ~/.local/share/   # or in $XDG_DATA_HOME, if defined
        Win 10:   C:\Users\<username>\AppData\Local\
    For Unix, we follow the XDG spec and support $XDG_DATA_HOME if defined.
    :param file_name: file to be fetched from the data dir
    :return: full path to the user-specific data dir
    """
    if sys.platform.startswith("win"):
        os_path = os.getenv("LOCALAPPDATA")
    elif sys.platform.startswith("darwin"):
        os_path = "~/Library/Application Support"
    else:
        # linux
        os_path = os.getenv("XDG_DATA_HOME", "~/.local/share")

    path = Path(os_path) / "fluxvault"
    # set fluxwallet datadir (this has to be set before any fluxwallet imports)

    return path.expanduser()


def generate_wallet():
    # this runs init for wallet, (config.py) sets up dirs etc
    # it's a pretty obscure interface - we set data dir in func above
    # as soon as you import somthing, it triggers initalize_lib()
    from fluxwallet.mnemonic import Mnemonic
    from fluxwallet.wallets import wallet_create_or_open

    mnemonic = Mnemonic().generate()
    # print(f"Mnemonic: {mnemonic}")

    # this needs to be interactive or something

    w = wallet_create_or_open("Payments", keys=mnemonic, network="flux")
    key = w.get_key()

    # print(f"receive address: {key.address}")


def first_run(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    os.environ["FW_INIT_DATA_DIR"] = str(root / ".wallet")

    db_dir = root / "db"
    generic_vault_dir = Path().home() / ".vault"

    db_dir.mkdir(parents=True, exist_ok=True)
    generic_vault_dir.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(db_dir / "fluxvault.db")
    cursor = con.cursor()
    cursor.execute(
        """CREATE TABLE STORED_KEYS
                   (id INTEGER PRIMARY KEY,
                   address varchar(35) NOT NULL)"""
    )

    # cursor.execute("INSERT INTO...
    # do database stuff
    generate_wallet()

    # print(
    #     "Opening generic vault directory, if you don't specify a vault dir when you create an app, this is where it will end up by default"
    # )
    # show_in_file_manager(str(generic_vault_dir))


def init_wallet():
    from fluxwallet.wallets import wallet_create_or_open

    # this will error if wallet doesn't exist
    payments = wallet_create_or_open("Payments", network="flux")


def setup_filesystem_and_wallet() -> Path:
    root = app_dir()
    if root.exists():
        init_wallet()
    else:
        first_run(root)
    return root


if __name__ == "__main__":
    setup_filesystem_and_wallet()
