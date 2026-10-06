"""Platform dispatcher for Chrome Companion local state."""
from __future__ import annotations

import os

if os.name == "nt":
    from chrome_companion.win32_state import *  # noqa: F401,F403
else:
    from chrome_companion.state_posix import *  # noqa: F401,F403
