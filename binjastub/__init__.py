import os
import sysconfig as sc
from pathlib import Path

# Hack to include z3 path for virtualenv installs
bin_path = Path(sc.get_paths()["purelib"]) / "bin"
if bin_path.exists():
    os.environ["PATH"] = str(bin_path) + ":" + os.environ.get("PATH", "")

import mui
