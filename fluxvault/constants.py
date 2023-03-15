from pathlib import Path

STATE_ROOT = Path("/data/")
WWW_ROOT = STATE_ROOT / "files"
STATEFILE = STATE_ROOT / ".fluxvault_agent.state"
STATE_SIG = STATE_ROOT / ".fluxvault_agent_state.sig"
VAULT_DIR = Path.home() / ".vault"
# PLUGIN_DIR = Path("/var/lib/fluxvault/plugins")
PLUGIN_DIR = Path("/tmp/plugins")
# SSL_DIR = Path("/etc/ssl")
SSL_DIR = Path("/tmp/ssl")
