import os
import z3
import sys
from pathlib import Path

# Hack to include z3 path for virtualenv installs
bin_path = Path(z3.__file__).parent.parent / "bin"
if bin_path.exists():
    os.environ["PATH"] = str(bin_path) + ":" + os.environ.get("PATH", "")

# Add parent directory to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import mui
