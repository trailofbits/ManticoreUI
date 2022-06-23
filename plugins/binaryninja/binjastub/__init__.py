import os
import z3
from pathlib import Path

# Hack to include z3 path for virtualenv installs
bin_path = Path(z3.__file__).parent.parent / "bin"
if bin_path.exists():
    os.environ["PATH"] = str(bin_path) + ":" + os.environ.get("PATH", "")

import mui
