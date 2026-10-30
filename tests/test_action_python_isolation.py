# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run the shell steps of action.yaml from a workspace holding planted modules.

Composite action steps run with the working directory set to the
caller's workspace. These tests run the steps the same way, from a
temporary directory holding Python files named after modules the steps
import. Each planted file records that it was imported, so the tests
can assert that the action only ever loads its own code.

Steps run as the runner runs composite bash steps
(bash --noprofile --norc -eo pipefail), and values a step appends to
GITHUB_ENV are passed on to the later steps.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_YAML = REPO_ROOT / "action.yaml"

# Imported by the Python calls in action.yaml after start-up;
# sitecustomize runs at start-up when the working directory is on
# PYTHONPATH.
PLANTED_MODULES = ("sitecustomize", "secrets", "datetime", "re")
PLANTED_PACKAGES = ("tag_validate", "json")

PLANTED_SOURCE = """\
import os
import sys

with open(os.environ["PLANTED_MARKER"], "a", encoding="utf-8") as marker:
    marker.write(__name__ + "\\n")
sys.exit(97)
"""

# The stubs log the PYTHONPATH they were started with: pip and the
# uvx console script are Python programs run as scripts, so an empty
# entry there would put the workspace on their sys.path.
STUB_UVX = """\
#!/usr/bin/env bash
# Stand-in for the PyPI CLI: copy STUB_REPORT to the --json-file path.
printf 'uvx %s\\n' "${PYTHONPATH-<unset>}" >> "${STUB_ENV_LOG}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--json-file" ]; then
    cp "${STUB_REPORT}" "$2"
  fi
  shift
done
"""

STUB_PIP = """\
#!/usr/bin/env bash
# The test interpreter already has the action's dependencies.
printf 'pip %s\\n' "${PYTHONPATH-<unset>}" >> "${STUB_ENV_LOG}"
exit 0
"""


def _load_action() -> dict[str, Any]:
    with ACTION_YAML.open(encoding="utf-8") as handle:
        action: dict[str, Any] = yaml.safe_load(handle)
    return action


def _step(name: str) -> dict[str, Any]:
    steps: list[dict[str, Any]] = _load_action()["runs"]["steps"]
    for step in steps:
        if step.get("name") == name:
            return step
    raise AssertionError(f"step {name!r} not found in {ACTION_YAML}")


def _input_defaults() -> dict[str, str]:
    inputs = _load_action()["inputs"]
    return {
        f"INPUTS_{name.upper()}": str(spec.get("default", ""))
        for name, spec in inputs.items()
    }


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _read_key_values(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key] = value
    return values


class ActionRunner:
    """Run action.yaml steps the way a composite action runs them."""

    def __init__(self, tmp_path: Path) -> None:
        self.workspace = tmp_path / "workspace"
        self.runner_temp = tmp_path / "runner-temp"
        self.bin_dir = tmp_path / "bin"
        for directory in (self.workspace, self.runner_temp, self.bin_dir):
            directory.mkdir()
        self.marker = tmp_path / "planted-ran"
        self.github_env = tmp_path / "github-env"
        self.github_output = tmp_path / "github-output"
        self.step_summary = tmp_path / "step-summary"
        for path in (self.github_env, self.github_output, self.step_summary):
            path.touch()
        self.report = tmp_path / "report.json"
        self.stub_env_log = tmp_path / "stub-env"

        # python/python3 resolve to the test interpreter, which has the
        # action's dependencies installed. A wrapper rather than a
        # symlink keeps a virtual environment's site-packages.
        for name in ("python", "python3"):
            _write_executable(
                self.bin_dir / name, f'#!/bin/sh\nexec "{sys.executable}" "$@"\n'
            )
        _write_executable(self.bin_dir / "uvx", STUB_UVX)
        _write_executable(self.bin_dir / "pip", STUB_PIP)

        self.inputs = _input_defaults()
        self.exported: dict[str, str] = {}

    def plant(self) -> None:
        for module in PLANTED_MODULES:
            (self.workspace / f"{module}.py").write_text(
                PLANTED_SOURCE, encoding="utf-8"
            )
        for package in PLANTED_PACKAGES:
            (self.workspace / package).mkdir()
            (self.workspace / package / "__init__.py").write_text(
                PLANTED_SOURCE, encoding="utf-8"
            )

    def set_report(self, text: str) -> None:
        self.report.write_text(text, encoding="utf-8")

    def run(self, step_name: str, repository: str) -> subprocess.CompletedProcess:
        step = _step(step_name)
        env = {
            "PATH": os.pathsep.join(
                [str(self.bin_dir), os.environ.get("PATH", os.defpath)]
            ),
            "HOME": os.environ.get("HOME", str(self.runner_temp)),
            "GITHUB_REPOSITORY": repository,
            "GITHUB_ENV": str(self.github_env),
            "GITHUB_OUTPUT": str(self.github_output),
            "GITHUB_STEP_SUMMARY": str(self.step_summary),
            "RUNNER_TEMP": str(self.runner_temp),
            "ACTION_PATH": str(REPO_ROOT),
            "PLANTED_MARKER": str(self.marker),
            "STUB_REPORT": str(self.report),
            "STUB_ENV_LOG": str(self.stub_env_log),
        }
        env.update(self.exported)
        env.update(self.inputs)

        script = self.runner_temp / "step.sh"
        script.write_text(step["run"], encoding="utf-8")
        bash = shutil.which("bash")
        assert bash, "bash is required to run the action steps"
        result = subprocess.run(
            [bash, "--noprofile", "--norc", "-eo", "pipefail", str(script)],
            cwd=self.workspace,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.exported.update(_read_key_values(self.github_env))
        return result

    def planted_imports(self) -> str:
        if self.marker.exists():
            return self.marker.read_text(encoding="utf-8")
        return ""

    def outputs(self) -> dict[str, str]:
        return _read_key_values(self.github_output)

    def stub_pythonpaths(self) -> list[str]:
        """The PYTHONPATH each pip or uvx stub call was started with."""
        if not self.stub_env_log.exists():
            return []
        return self.stub_env_log.read_text(encoding="utf-8").splitlines()


@pytest.fixture
def runner(tmp_path: Path) -> ActionRunner:
    action_runner = ActionRunner(tmp_path)
    action_runner.plant()
    action_runner.inputs.update(
        {
            "INPUTS_TAG_STRING": "v1.2.3",
            "INPUTS_REQUIRE_TYPE": "semver",
        }
    )
    return action_runner


def _assert_semver_outputs(action_runner: ActionRunner) -> None:
    outputs = action_runner.outputs()
    assert outputs["valid"] == "true"
    assert outputs["tag_type"] == "semver"
    assert outputs["tag_name"] == "v1.2.3"
    pretty = Path(outputs["artifact_path"]) / "tag-validation-pretty.json"
    assert json.loads(pretty.read_text(encoding="utf-8"))["success"] is True


def test_validate_step_ignores_workspace_modules_with_pypi_cli(
    runner: ActionRunner,
) -> None:
    """The default (uvx) route imports nothing from the workspace."""
    runner.set_report(
        json.dumps(
            {
                "success": True,
                "version": "v1.2.3",
                "detected_type": "semver",
                "version_prefix": True,
            }
        )
    )

    result = runner.run("Validate tag", repository="example-org/caller")

    assert result.returncode == 0, result.stdout + result.stderr
    assert runner.planted_imports() == ""
    _assert_semver_outputs(runner)


@pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="the action runs its local code on Python 3.12 with -P (3.11+)",
)
def test_local_code_steps_ignore_workspace_modules(runner: ActionRunner) -> None:
    """use_local_action imports tag_validate from src/, not the workspace."""
    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "true"

    for step_name in (
        "Install local dependencies",
        "Verify Python module import",
        "Validate tag",
    ):
        result = runner.run(step_name, repository="example-org/caller")
        assert result.returncode == 0, f"{step_name}: {result.stdout}{result.stderr}"
        assert runner.planted_imports() == "", step_name

    # The caller's later steps must not inherit the action's PYTHONPATH
    assert "PYTHONPATH" not in runner.exported
    _assert_semver_outputs(runner)


@pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="the action runs its local code on Python 3.12 with -P (3.11+)",
)
def test_local_code_steps_ignore_inherited_empty_pythonpath(
    runner: ActionRunner,
) -> None:
    """An inherited PYTHONPATH with an empty entry does not reach sys.path.

    -P does not drop an empty PYTHONPATH entry, which names the working
    directory and makes Python run a sitecustomize.py found there, so
    the local steps must not carry the inherited value over.
    """
    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "true"
    runner.exported["PYTHONPATH"] = ":"

    for step_name in ("Verify Python module import", "Validate tag"):
        result = runner.run(step_name, repository="example-org/caller")
        assert result.returncode == 0, f"{step_name}: {result.stdout}{result.stderr}"
        assert runner.planted_imports() == "", step_name
    _assert_semver_outputs(runner)


def test_pip_and_uvx_do_not_inherit_empty_pythonpath(runner: ActionRunner) -> None:
    """pip and the uvx CLI start without an inherited PYTHONPATH.

    Both run as scripts, so an empty PYTHONPATH entry would name the
    working directory, the caller's workspace, and make them import
    from it, including a sitecustomize.py at start-up.
    """
    runner.exported["PYTHONPATH"] = ":"
    runner.set_report(
        json.dumps(
            {
                "success": True,
                "version": "v1.2.3",
                "detected_type": "semver",
                "version_prefix": True,
            }
        )
    )

    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "true"
    result = runner.run("Install local dependencies", repository="example-org/caller")
    assert result.returncode == 0, result.stdout + result.stderr
    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "false"
    result = runner.run("Validate tag", repository="example-org/caller")
    assert result.returncode == 0, result.stdout + result.stderr

    assert runner.stub_pythonpaths() == ["pip <unset>", "uvx <unset>"]
    _assert_semver_outputs(runner)


# Closes a ''' string and appends to the marker file if run as Python;
# also holds a backslash and a newline.
QUOTED_TAG = (
    "v1'''+str(open(__import__('os').environ['PLANTED_MARKER'], 'a')"
    ".write('report text ran'))+'''\\b\nc"
)


def test_json_check_reads_report_as_data(runner: ActionRunner) -> None:
    """A report with ''', a backslash and a newline passes, running nothing."""
    report = json.dumps(
        {"success": True, "version": QUOTED_TAG, "detected_type": "other"}
    )
    runner.inputs.update({"INPUTS_TAG_STRING": QUOTED_TAG, "INPUTS_REQUIRE_TYPE": ""})
    runner.set_report(report)

    result = runner.run("Validate tag", repository="example-org/caller")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Invalid JSON" not in result.stderr
    assert runner.planted_imports() == ""
    pretty = Path(runner.outputs()["artifact_path"]) / "tag-validation-pretty.json"
    assert json.loads(pretty.read_text(encoding="utf-8")) == json.loads(report)


def test_invalid_json_disables_upload(runner: ActionRunner) -> None:
    """A report that is not JSON skips the artefact with the usual warning."""
    runner.set_report('{"success": true, "version": "v1.2.3"')

    result = runner.run("Validate tag", repository="example-org/caller")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Warning: Invalid JSON for artifact upload" in result.stderr
    assert "Continuing without artifact upload..." in result.stderr
    assert runner.outputs()["artifact_path"] == ""
    assert not list(runner.runner_temp.glob("tag-validate-*"))
    assert runner.planted_imports() == ""


def _setup_uv_lookup(
    step_env: dict[str, str], workspace: Path, action_dir: Path
) -> subprocess.CompletedProcess:
    """Run setup-uv's 'uv python find' as the Install uv step would."""
    # setup-uv's default working-directory is the workspace
    working_directory = (
        str(
            (_step("Install uv").get("with") or {}).get(
                "working-directory", "${{ github.workspace }}"
            )
        )
        .replace("${{ github.workspace }}", str(workspace))
        .replace("${{ github.action_path }}", str(action_dir))
    )
    # A runner job has no virtual environment active; the one running
    # these tests would otherwise be found before any .venv.
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"VIRTUAL_ENV", "CONDA_PREFIX"} and not key.startswith("UV_")
    }
    env.update(step_env)
    return subprocess.run(
        ["uv", "python", "find", "--directory", working_directory],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv on PATH")
@pytest.mark.parametrize(
    "action_inside_workspace",
    [False, True],
    ids=["action-outside-workspace", "action-inside-workspace"],
)
def test_setup_uv_ignores_workspace_python_version(
    tmp_path: Path, action_inside_workspace: bool
) -> None:
    """setup-uv's interpreter lookup uses nothing from the workspace.

    setup-uv runs 'uv python find --directory <working-directory>' and
    starts the interpreter it reports, so this runs that call under
    the env and working-directory the action gives the step. The
    workspace holds a .python-version naming a script, and a .venv
    whose interpreters are scripts; each records that it ran. The
    action directory is outside the workspace, as for a published
    action, or below it, as for a caller using the action from its own
    checkout. There the .venv is in a parent of the action directory,
    and only UV_SYSTEM_PYTHON keeps the lookup from running it, which
    the test also checks by running the lookup without it.
    """
    workspace = tmp_path / "workspace"
    if action_inside_workspace:
        action_dir = workspace / "actions" / "tag-validate-action"
    else:
        action_dir = tmp_path / "_actions" / "tag-validate-action"
    venv_bin = workspace / ".venv" / "bin"
    for directory in (workspace, action_dir, venv_bin):
        directory.mkdir(parents=True)
    for name in ("action.yaml", "pyproject.toml"):
        shutil.copy(REPO_ROOT / name, action_dir / name)
    marker = tmp_path / "planted-ran"
    pinned = workspace / "planted-python"
    _write_executable(pinned, f'#!/bin/sh\necho uv-pin >> "{marker}"\nexit 1\n')
    (workspace / ".python-version").write_text(f"{pinned}\n", encoding="utf-8")
    (workspace / ".venv" / "pyvenv.cfg").write_text(
        "home = /usr/bin\nversion = 3.12.0\n", encoding="utf-8"
    )
    for name in ("python", "python3"):
        _write_executable(
            venv_bin / name, f'#!/bin/sh\necho workspace-venv >> "{marker}"\nexit 1\n'
        )

    step_env = {
        key: str(value) for key, value in (_step("Install uv").get("env") or {}).items()
    }
    result = _setup_uv_lookup(step_env, workspace, action_dir)

    planted = marker.read_text(encoding="utf-8") if marker.exists() else ""
    assert planted == "", result.stdout + result.stderr
    assert result.returncode == 0, result.stdout + result.stderr

    if action_inside_workspace:
        # Control: without UV_SYSTEM_PYTHON the lookup runs the .venv
        # interpreter in the action directory's parent.
        step_env.pop("UV_SYSTEM_PYTHON", None)
        _setup_uv_lookup(step_env, workspace, action_dir)
        assert "workspace-venv" in marker.read_text(encoding="utf-8")
