import asyncio
import importlib
import os
import stat
import subprocess
import sys
from multiprocessing import Manager, cpu_count
from pathlib import Path
from queue import Empty

from fluxvault.extensions import FluxVaultExtensions

plugin = FluxVaultExtensions(plugin_name="vanity_finder", required_packages=[])


@plugin.create
def chmod_x_file(file):
    st = os.stat(file)
    os.chmod(file, st.st_mode | stat.S_IEXEC)


@plugin.create
@plugin.pass_storage
async def stop_workers(storage):
    if storage.get("continue_running"):
        storage["continue_running"] = False
        storage["stop_event"].set()


@plugin.create
@plugin.pass_storage
async def check_workers(storage):
    best = storage.get("best", "t1")
    update_queue = storage.get("update_queue")
    response_queue = storage.get("response_queue")

    try:
        response = response_queue.get(block=False)
    except Empty:
        response = None

    if response:
        storage["continue_running"] = False
        storage["stop_event"].set()
        return {"best": "", "result": response}

    while True:
        try:
            message = update_queue.get(block=False)
        except Empty:
            storage["best"] = best
            return {"best": best, "result": None}

        if len(message) > len(best):
            best = message


@plugin.create
@plugin.pass_storage
async def run_file(storage: dict, file: str, packages: list, *args, **kwargs):

    # ToDo: use this instead of adding to path

    # import importlib.util
    # spec = importlib.util.spec_from_file_location("module.name", "/path/to/file.py")
    # foo = importlib.util.module_from_spec(spec)
    # spec.loader.exec_module(foo)
    # foo.MyClass()

    p = Path(f"{file}.py")

    if not p.exists() or p.stat().st_size == 0:
        print("File doesn't exist")
        return

    sys.path.append(str(p.parent))

    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install"] + packages,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        print("Subprocess error")
        return

    manager = Manager()
    stop_event = manager.Event()
    update_queue = manager.Queue()
    response_queue = manager.Queue()

    storage["stop_event"] = stop_event
    storage["update_queue"] = update_queue
    storage["response_queue"] = response_queue
    storage["continue_running"] = True

    importlib.invalidate_caches()
    try:
        runner = importlib.import_module(p.stem)
    except Exception as e:
        print(repr(e))
        return

    while storage["continue_running"]:
        if response_queue.empty():
            await runner.main(
                stop_event,
                update_queue,
                response_queue,
                cpu_count() // 2,
                *args,
                **kwargs,
            )
        await asyncio.sleep(1)

    del storage["stop_event"]
    del storage["update_queue"]
    del storage["response_queue"]
    del storage["continue_running"]
    del storage["best"]
