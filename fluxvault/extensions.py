from aiotinyrpc.dispatch import RPCDispatcher


class FluxVaultExtensions(RPCDispatcher):
    """Wrapper to keep dispatcher internal to FluxVault"""

    def __init__(self):
        super().__init__()
