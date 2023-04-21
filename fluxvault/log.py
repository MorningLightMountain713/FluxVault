import logging

from rich.logging import RichHandler
from logging.handlers import QueueHandler, QueueListener
import queue


def configure_logs(log_to_file, logfile_path, debug):
    # vault_log = logging.getLogger("fluxvault")
    # fluxrpc_log = logging.getLogger("fluxrpc")
    level = logging.DEBUG if debug else logging.INFO
    # logging.getLogger("fluxvault")
    # logging.getLogger("fluxrpc")
    # formatter = logging.Formatter(
    #     "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    # )

    # vault_log.setLevel("NOTSET")
    # fluxrpc_log.setLevel("NOTSET")

    # # stream_handler = logging.StreamHandler()
    # stream_handler = RichHandler(level="NOTSET")
    # stream_handler.setFormatter(formatter)

    # file_handler = logging.FileHandler(logfile_path, mode="a")
    # file_handler.setFormatter(formatter)

    # vault_log.addHandler(stream_handler)
    # fluxrpc_log.addHandler(stream_handler)
    # if log_to_file:
    #     fluxrpc_log.addHandler(file_handler)
    #     vault_log.addHandler(file_handler)

    # logging.basicConfig(level="NOTSET", handlers=[RichHandler(level="NOTSET")])
    # logger = logging.getLogger('rich')

    ...


# formatter = logging.Formatter(
#     "%(asctime)s: fluxvault: %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"
# )

# que = queue.Queue(-1)  # no limit on size
# queue_handler = QueueHandler(que)
# handler = logging.StreamHandler()
# listener = QueueListener(que, handler)

format = "%(name)s: %(message)s"

logging.basicConfig(
    level="INFO",
    format=format,
    datefmt="%d/%m/%y %H:%M:%S%z",
    handlers=[RichHandler(level="NOTSET")],
)
# logging.getLogger("asyncio").setLevel(logging.DEBUG)
log = logging.getLogger("fluxvault")

# log.addHandler(queue_handler)
# listener.start()
