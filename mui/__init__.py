__version__ = "0.1.0"

import os
import sys
from pathlib import Path
from binaryninja import Settings

# Egg-link files created by Pip are currently not honored by Binary Ninja
# This hack adds manticore to the python path manually so it can be imported
current_fold_path = os.path.dirname(os.path.realpath(__file__))
manticore_path = str(Path(current_fold_path, "../manticore").resolve())
if manticore_path not in sys.path:
    sys.path.append(manticore_path)


# Adding virtualenv binaries to PATH so that z3 can be found by manticore
venv_path = Settings().get_string("python.virtualenv")
if venv_path != "":
    venv_bin_path = str(Path(venv_path, "../../../bin/").resolve())
    if venv_bin_path not in os.environ["PATH"]:
        os.environ["PATH"] = f'{os.environ["PATH"]}:{venv_bin_path}'

# Adding ~/.local/bin to path so solc can be used by crytic-compile
local_bin_path = Path(os.path.expanduser("~"), ".local/bin").resolve()
if local_bin_path.is_dir() and str(local_bin_path) not in os.environ["PATH"]:
    os.environ["PATH"] = f'{os.environ["PATH"]}:{str(local_bin_path)}'

from . import mui
