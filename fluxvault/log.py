import logging


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


log = logging.getLogger("fluxvault")
