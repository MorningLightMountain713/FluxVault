from fluxrpc.dispatch import RPCDispatcher


class FluxVaultExtensions(RPCDispatcher):
    """Wrapper to keep dispatcher internal to FluxVault"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
