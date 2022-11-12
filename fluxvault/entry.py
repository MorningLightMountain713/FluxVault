import daemon


def blah():

    with daemon.DaemonContext():
        import fluxvault.cli

        fluxvault.cli.app()
