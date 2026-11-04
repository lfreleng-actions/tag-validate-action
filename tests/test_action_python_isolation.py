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
GITHUB_ENV are passed on to the later steps. PYTHON and UV stand in
for the setup-python and setup-uv outputs; python, python3, pip, uv
and uvx on PATH are planted too, so a step that looks one up there
records it.
"""

from __future__ import annotations

import json
import os
import re
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
import re
import sys

with open(os.environ["PLANTED_MARKER"], "a", encoding="utf-8") as marker:
    marker.write(__name__ + "\\n")
sys.exit(97)
"""

PLANTED_COMMAND = """\
#!/bin/sh
echo "$(basename "$0") on PATH" >> "${PLANTED_MARKER}"
exit 97
"""
PLANTED_COMMANDS = ("python", "python3", "pip", "uv", "uvx")

# The uv stub logs the PYTHONPATH it was started with: the uvx console
# script is a Python program run without -I, so a PYTHONPATH entry
# naming the workspace would make it import from there.
STUB_UV = """\
#!/usr/bin/env bash
# Stand-in for 'uv tool run ... tag-validate': copy STUB_REPORT to the
# --json-file path.
printf 'uv %s\\n' "${PYTHONPATH-<unset>}" >> "${STUB_ENV_LOG}"
printf '%s\\n' "$*" >> "${STUB_ARGS_LOG}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--json-file" ]; then
    cp "${STUB_REPORT}" "$2"
  fi
  shift
done
"""

# The trusted interpreter: the test interpreter, which already has the
# action's dependencies, so pip itself is not run. A wrapper rather
# than a symlink keeps a virtual environment's site-packages. The pip
# call logs the Python start-up variables it inherited, which pip's
# build subprocesses would see; the log path is written in, since pip
# runs with an empty environment.
STUB_PYTHON = """\
#!/usr/bin/env bash
if [ "$1 $2 $3 $4" = "-I -m pip install" ]; then
  inherited=$(compgen -e | grep -E '^(PYTHON|__PYVENV_LAUNCHER__)' | sort)
  printf 'python %s [%s]\\n' "$*" "$(echo ${{inherited}})" >> "{env_log}"
  exit 0
fi
exec "{python}" "$@"
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


def _pip_requirements() -> list[str]:
    run = _step("Install local dependencies")["run"]
    line = next(line for line in run.splitlines() if "-m pip install" in line)
    return [arg.strip('"') for arg in line.split("pip install ", 1)[1].split()]


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
        self.tool_dir = tmp_path / "tools"
        for directory in (
            self.workspace,
            self.runner_temp,
            self.bin_dir,
            self.tool_dir,
        ):
            directory.mkdir()
        self.marker = tmp_path / "planted-ran"
        self.github_env = tmp_path / "github-env"
        self.github_output = tmp_path / "github-output"
        self.step_summary = tmp_path / "step-summary"
        for path in (self.github_env, self.github_output, self.step_summary):
            path.touch()
        self.report = tmp_path / "report.json"
        self.stub_env_log = tmp_path / "stub-env"
        self.stub_args_log = tmp_path / "stub-args"

        for name in PLANTED_COMMANDS:
            _write_executable(self.bin_dir / name, PLANTED_COMMAND)
        self.python = self.tool_dir / "python"
        self.uv = self.tool_dir / "uv"
        _write_executable(
            self.python,
            STUB_PYTHON.format(env_log=self.stub_env_log, python=sys.executable),
        )
        _write_executable(self.uv, STUB_UV)

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
            "STUB_ARGS_LOG": str(self.stub_args_log),
        }
        env.update(self.exported)
        env.update(self.inputs)
        # The step's own env block, as the runner sets it, over the
        # values exported by earlier steps
        step_env = step.get("env") or {}
        if "PYTHON" in step_env:
            env["PYTHON"] = str(self.python)
        if "UV" in step_env:
            env["UV"] = str(self.uv)

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

    def uv_calls(self) -> list[str]:
        """The arguments of each uv stub call."""
        if not self.stub_args_log.exists():
            return []
        return self.stub_args_log.read_text(encoding="utf-8").splitlines()

    def planted_imports(self) -> str:
        if self.marker.exists():
            return self.marker.read_text(encoding="utf-8")
        return ""

    def outputs(self) -> dict[str, str]:
        return _read_key_values(self.github_output)

    def stub_pythonpaths(self) -> list[str]:
        """The logged pip and uv calls.

        The pip line lists the PYTHON* names pip inherited; each uv line,
        the PYTHONPATH that call started with.
        """
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
    [call] = runner.uv_calls()
    assert call.startswith(
        f"tool run --no-config --python {runner.python} --quiet "
        "--from tag-validate tag-validate validate v1.2.3 "
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


def test_local_code_steps_ignore_inherited_empty_pythonpath(
    runner: ActionRunner,
) -> None:
    """An inherited PYTHONPATH naming the workspace does not reach sys.path.

    An empty PYTHONPATH entry names the working directory and makes
    Python run a sitecustomize.py found there; -I ignores PYTHONPATH.
    """
    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "true"
    runner.exported["PYTHONPATH"] = ":"

    for step_name in ("Verify Python module import", "Validate tag"):
        result = runner.run(step_name, repository="example-org/caller")
        assert result.returncode == 0, f"{step_name}: {result.stdout}{result.stderr}"
        assert runner.planted_imports() == "", step_name
    _assert_semver_outputs(runner)


def test_local_code_steps_ignore_inherited_executable(runner: ActionRunner) -> None:
    """PYTHONEXECUTABLE and __PYVENV_LAUNCHER__ do not move sys.prefix.

    -I does not cover either: each sets sys.executable, and a
    pyvenv.cfg beside the named file makes Python load that
    directory's site-packages, here a sitecustomize.py.
    """
    venv = runner.workspace / ".venv"
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages = venv / "lib" / version / "site-packages"
    site_packages.mkdir(parents=True)
    (site_packages / "sitecustomize.py").write_text(PLANTED_SOURCE, encoding="utf-8")
    (venv / "pyvenv.cfg").write_text(
        f"home = {Path(sys.base_prefix) / 'bin'}\n", encoding="utf-8"
    )
    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "true"

    for variable in ("PYTHONEXECUTABLE", "__PYVENV_LAUNCHER__"):
        runner.exported = {variable: str(venv / "bin" / "python")}
        for step_name in ("Verify Python module import", "Validate tag"):
            result = runner.run(step_name, repository="example-org/caller")
            assert result.returncode == 0, (
                f"{variable} {step_name}: {result.stdout}{result.stderr}"
            )
            assert runner.planted_imports() == "", (variable, step_name)
    _assert_semver_outputs(runner)


def test_pip_and_uvx_do_not_inherit_empty_pythonpath(runner: ActionRunner) -> None:
    """pip and the uvx CLI start without an inherited PYTHONPATH.

    pip runs under -I, which ignores PYTHONPATH. The uvx CLI is a
    console script, so the step drops PYTHONPATH before it starts it;
    an empty entry would name the working directory, the caller's
    workspace, and make it import from there, including a
    sitecustomize.py at start-up.
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

    assert runner.stub_pythonpaths() == [
        "python -I -m pip install " + " ".join(_pip_requirements()) + " []",
        "uv <unset>",
    ]
    assert runner.planted_imports() == ""
    _assert_semver_outputs(runner)


def test_pip_starts_with_no_python_settings(runner: ActionRunner) -> None:
    """pip, and so its build subprocesses, inherit no PYTHON* settings.

    -I covers only the interpreter it starts: pip runs build backends
    as plain subprocesses, where an inherited PYTHONHOME breaks the
    build and PYTHONPATH or PYTHONSTARTUP load the caller's code.
    """
    runner.inputs["INPUTS_USE_LOCAL_ACTION"] = "true"
    runner.exported.update(
        {
            "PYTHONPATH": ":",
            "PYTHONHOME": str(runner.workspace),
            "PYTHONSTARTUP": str(runner.workspace / "sitecustomize.py"),
            "PYTHONEXECUTABLE": str(runner.workspace / "python"),
            "__PYVENV_LAUNCHER__": str(runner.workspace / "python"),
        }
    )

    result = runner.run("Install local dependencies", repository="example-org/caller")

    assert result.returncode == 0, result.stdout + result.stderr
    assert runner.stub_pythonpaths() == [
        "python -I -m pip install " + " ".join(_pip_requirements()) + " []"
    ]
    assert runner.planted_imports() == ""


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
    caller_env: dict[str, str],
    step_env: dict[str, str],
    workspace: Path,
    action_dir: Path,
) -> subprocess.CompletedProcess:
    """Run setup-uv's 'uv python find' as the Install uv step would.

    caller_env stands for what the caller's earlier steps exported;
    the step's own env block is set over it, as the runner does.
    """
    expressions = {
        "${{ github.workspace }}": str(workspace),
        "${{ github.action_path }}": str(action_dir),
        "${{ runner.temp }}": str(workspace.parent / "runner-temp"),
    }

    def expand(value: object) -> str:
        text = str(value)
        for expression, replacement in expressions.items():
            text = text.replace(expression, replacement)
        return text

    # setup-uv's default working-directory is the workspace
    working_directory = expand(
        (_step("Install uv").get("with") or {}).get(
            "working-directory", "${{ github.workspace }}"
        )
    )
    # A runner job has no virtual environment active; the one running
    # these tests would otherwise be found.
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"VIRTUAL_ENV", "CONDA_PREFIX"} and not key.startswith("UV_")
    }
    env.update(caller_env)
    env.update({key: expand(value) for key, value in step_env.items()})
    return subprocess.run(
        ["uv", "python", "find", "--directory", working_directory],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv on PATH")
@pytest.mark.parametrize("selector", ["request", "active-environment"])
@pytest.mark.parametrize(
    "action_inside_workspace",
    [False, True],
    ids=["action-outside-workspace", "action-inside-workspace"],
)
def test_setup_uv_lookup_runs_no_caller_interpreter(
    tmp_path: Path, selector: str, action_inside_workspace: bool
) -> None:
    """setup-uv's interpreter lookup starts nothing a caller chose.

    setup-uv runs 'uv python find --directory <working-directory>' and
    starts the interpreter it reports, so this runs that call under
    the env and working-directory the action gives the step, with
    caller variables naming interpreters in the workspace: requested
    ones (UV_PYTHON, ...) or an active environment (VIRTUAL_ENV, ...).
    Each planted interpreter records that it ran. The step's invalid
    UV_PYTHON_PREFERENCE makes uv refuse its arguments before any
    lookup; the control shows that, without it, uv runs one.
    """
    workspace = tmp_path / "workspace"
    if action_inside_workspace:
        action_dir = workspace / "actions" / "tag-validate-action"
    else:
        action_dir = tmp_path / "_actions" / "tag-validate-action"
    venv = workspace / ".venv"
    venv_bin = venv / "bin"
    for directory in (workspace, action_dir, venv_bin, venv / "conda-meta"):
        directory.mkdir(parents=True)
    for name in ("action.yaml", "pyproject.toml"):
        shutil.copy(REPO_ROOT / name, action_dir / name)
    marker = tmp_path / "planted-ran"
    (venv / "pyvenv.cfg").write_text(
        "home = /usr/bin\nversion = 3.12.0\n", encoding="utf-8"
    )
    for name in ("python", "python3", "python3.12", "python3.13"):
        _write_executable(
            venv_bin / name, f'#!/bin/sh\necho {name} >> "{marker}"\nexit 1\n'
        )
    (workspace / ".python-version").write_text(
        f"{venv_bin / 'python'}\n", encoding="utf-8"
    )

    caller_env = {"PATH": f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}"}
    if selector == "request":
        caller_env.update(
            {
                "UV_PYTHON": str(venv_bin / "python"),
                "UV_PYTHON_SEARCH_PATH": str(venv_bin),
                "UV_PYTHON_INSTALL_DIR": str(workspace / "uv-python"),
                "UV_PYTHON_PREFERENCE": "only-system",
            }
        )
    else:
        caller_env.update(
            {
                "VIRTUAL_ENV": str(venv),
                "CONDA_PREFIX": str(venv),
                "CONDA_DEFAULT_ENV": "base",
                "UV_INTERNAL__PARENT_INTERPRETER": str(venv_bin / "python"),
            }
        )

    step_env = {
        key: str(value) for key, value in (_step("Install uv").get("env") or {}).items()
    }
    result = _setup_uv_lookup(caller_env, step_env, workspace, action_dir)

    planted = marker.read_text(encoding="utf-8") if marker.exists() else ""
    assert planted == "", result.stdout + result.stderr
    assert result.returncode != 0
    assert "lookup-disabled" in result.stderr

    # Control: without the invalid preference the lookup runs one of
    # the planted interpreters.
    step_env.pop("UV_PYTHON_PREFERENCE")
    control = _setup_uv_lookup(caller_env, step_env, workspace, action_dir)
    assert marker.exists(), control.stdout + control.stderr


# The interpreter every uv and Python start in action.yaml must name
TRUSTED_PYTHON = "${{ steps.setup-python.outputs.python-path }}"
TRUSTED_UV = "${{ steps.setup-uv.outputs.uv-path }}"

SETUP_UV_WITH = {
    "working-directory": "${{ github.action_path }}",
    "tool-bin-dir": "${{ runner.temp }}/tag-validate-action/bin",
    "enable-cache": False,
}
SETUP_UV_ENV = {
    "UV_NO_CONFIG": "1",
    "UV_NO_PROJECT": "1",
    "UV_PYTHON_PREFERENCE": "lookup-disabled",
    "UV_PYTHON_ARCH": "",
    "UV_PYTHON_INSTALL_DIR": "${{ runner.temp }}/tag-validate-action/python",
}

# A uv, uvx, python, python3 or pip command word, looked up on PATH
BARE_COMMAND = re.compile(r"(?:^|[\s;&|(])(uvx?|python3?(?:\.\d+)?|pip3?)(?=\s|$)")


def _shell_steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = _load_action()["runs"]["steps"]
    return [step for step in steps if "run" in step]


def _command_lines(script: str) -> list[str]:
    """Lines of a step script that run commands, without comments or echo."""
    lines = []
    in_heredoc = False
    for raw in script.splitlines():
        line = raw.strip()
        if in_heredoc:
            in_heredoc = line not in ("PYEOF", "EOFOUTPUT")
            continue
        if "<< 'PYEOF'" in line or "<< 'EOFOUTPUT'" in line:
            in_heredoc = True
        if not line or line.startswith("#") or line.startswith("echo "):
            continue
        lines.append(line)
    return lines


def test_setup_uv_step_contract() -> None:
    """The setup-uv step takes the guarded form, exactly."""
    step = _step("Install uv")
    assert step.get("id") == "setup-uv"
    assert step["with"] == SETUP_UV_WITH
    assert {key: str(value) for key, value in step["env"].items()} == SETUP_UV_ENV


def test_steps_start_only_the_trusted_interpreter() -> None:
    """No step finds uv or Python on PATH; each names the trusted one.

    Every uv call passes --python "${PYTHON}", and every Python start
    is "${PYTHON}" -I, where PYTHON is setup-python's python-path.
    """
    for step in _shell_steps():
        name = step["name"]
        env = step.get("env") or {}
        for line in _command_lines(step["run"]):
            # A module name after -m is not a command
            command = re.sub(r"\s-m\s+\S+", " ", line)
            assert not BARE_COMMAND.search(command), f"{name}: {line}"
            if '"${UV}"' in line:
                assert env.get("UV") == TRUSTED_UV, name
                assert '--python "${PYTHON}"' in line, f"{name}: {line}"
                assert "--no-config" in line, f"{name}: {line}"
            for match in re.finditer(r'"\$\{PYTHON\}"', line):
                assert env.get("PYTHON") == TRUSTED_PYTHON, name
                before = line[: match.start()]
                after = line[match.end() :]
                assert before.endswith("--python ") or after.startswith(" -I "), (
                    f"{name}: {line}"
                )


UV_PATH_GUARD = "Check uv PATH setting"


def test_uv_path_guard_runs_right_before_setup_uv() -> None:
    """The guard runs whenever setup-uv does, and just before it."""
    steps: list[dict[str, Any]] = _load_action()["runs"]["steps"]
    names = [step.get("name") for step in steps]
    index = names.index("Install uv")
    guard = steps[index - 1]
    assert guard.get("name") == UV_PATH_GUARD
    assert guard.get("if") == steps[index].get("if")


@pytest.mark.parametrize("value", ["", "1"])
def test_uv_path_guard_refuses_uv_no_modify_path(
    runner: ActionRunner, value: str
) -> None:
    """UV_NO_MODIFY_PATH, even empty, stops the action before setup-uv.

    setup-uv leaves PATH alone whenever the variable is defined, then
    runs a bare uv, which PATH resolves to the caller's.
    """
    runner.exported["UV_NO_MODIFY_PATH"] = value

    result = runner.run(UV_PATH_GUARD, repository="example-org/caller")

    assert result.returncode != 0
    assert "UV_NO_MODIFY_PATH" in result.stdout + result.stderr
    assert runner.planted_imports() == ""


def test_uv_path_guard_passes_without_uv_no_modify_path(
    runner: ActionRunner,
) -> None:
    result = runner.run(UV_PATH_GUARD, repository="example-org/caller")

    assert result.returncode == 0, result.stdout + result.stderr
    assert runner.planted_imports() == ""
