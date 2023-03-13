from pathlib import Path

STATE_ROOT = Path("/tmp/data/")
WWW_ROOT = STATE_ROOT / "files"
STATEFILE = STATE_ROOT / ".fluxvault_agent.state"
STATE_SIG = STATE_ROOT / ".fluxvault_agent_state.sig"
