import os
import sys
from distutils.dir_util import copy_tree
from pathlib import Path

import z3

DIR = os.path.dirname(__file__)

# Hack to include z3 path for virtualenv installs
bin_path = Path(z3.__file__).parent.parent / "bin"
if bin_path.exists():
    os.environ["PATH"] = str(bin_path) + ":" + os.environ.get("PATH", "")

# Add parent directory to sys.path
sys.path.append(os.path.join(DIR, ".."))

# Copy common files
copy_tree(os.path.join(DIR, "../../common"), os.path.join(DIR, "../mui/common_resources"), update=1)

import mui
