# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run the tag-validate CLI from this checkout's src/ directory.

action.yaml starts this file with 'python -I', which keeps the working
directory off sys.path and ignores PYTHONPATH, so the action's own
modules are added to sys.path here instead.
"""

import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
runpy.run_module("tag_validate.cli", run_name="__main__", alter_sys=True)
