#!/usr/bin/env python3
"""Validate deploy/arm-lsm-ostree.sh without touching host boot config."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "deploy" / "arm-lsm-ostree.sh"


def write_mock_rpm_ostree(path: Path, state: Path, calls: Path) -> None:
    path.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
STATE={state}
CALLS={calls}

if [[ "$1" == "kargs" && "$#" -eq 1 ]]; then
    cat "$STATE"
    exit 0
fi

echo "$*" >> "$CALLS"
if [[ "$1" == "kargs" && "$2" == --append=lsm=* ]]; then
    desired="${{2#--append=lsm=}}"
    printf 'quiet lsm=%s\\n' "$desired" > "$STATE"
elif [[ "$1" == "kargs" && "$2" == --replace=lsm=* ]]; then
    rest="${{2#--replace=lsm=}}"
    desired="${{rest#*=}}"
    printf 'quiet lsm=%s\\n' "$desired" > "$STATE"
fi
""",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_helper(tmp: Path, live_lsm: str, kargs: str, *, ostree: bool = True):
    lsm = tmp / "lsm"
    lsm.write_text(live_lsm, encoding="utf-8")
    booted = tmp / "ostree-booted"
    if ostree:
        booted.touch()
    state = tmp / "kargs"
    state.write_text(kargs, encoding="utf-8")
    calls = tmp / "calls"
    rpm = tmp / "rpm-ostree"
    write_mock_rpm_ostree(rpm, state, calls)

    env = os.environ.copy()
    env.update(
        {
            "JINNGUARD_OSTREE_BOOTED_PATH": str(booted),
            "JINNGUARD_LSM_PATH": str(lsm),
            "JINNGUARD_RPM_OSTREE": str(rpm),
        }
    )
    result = subprocess.run(
        [str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result, state, calls


def calls_text(calls: Path) -> str:
    return calls.read_text(encoding="utf-8") if calls.exists() else ""


def assert_contains_all(value: str, modules: list[str]) -> None:
    actual = set(value.split(","))
    missing = [module for module in modules if module not in actual]
    assert not missing, f"{value!r} dropped modules: {missing!r}"


def test_non_ostree_noop() -> None:
    with tempfile.TemporaryDirectory() as raw:
        result, _state, calls = run_helper(
            Path(raw), "lockdown,capability,yama", "quiet\n", ostree=False
        )
        assert result.returncode == 0, result.stderr
        assert "no-op" in result.stdout
        assert calls_text(calls) == ""


def test_append_preserves_live_lsm_modules() -> None:
    with tempfile.TemporaryDirectory() as raw:
        result, state, calls = run_helper(
            Path(raw), "lockdown,capability,selinux", "quiet\n"
        )
        assert result.returncode == 0, result.stderr
        assert "--append=lsm=lockdown,capability,selinux,bpf" in calls_text(calls)
        desired = state.read_text(encoding="utf-8").strip().split("lsm=", 1)[1]
        assert_contains_all(desired, ["lockdown", "capability", "selinux", "bpf"])


def test_replace_preserves_live_lsm_modules() -> None:
    with tempfile.TemporaryDirectory() as raw:
        result, state, calls = run_helper(
            Path(raw),
            "lockdown,capability,landlock,yama",
            "quiet lsm=lockdown,capability\n",
        )
        assert result.returncode == 0, result.stderr
        assert (
            "--replace=lsm=lockdown,capability=lockdown,capability,landlock,yama,bpf"
            in calls_text(calls)
        )
        desired = state.read_text(encoding="utf-8").strip().split("lsm=", 1)[1]
        assert_contains_all(
            desired, ["lockdown", "capability", "landlock", "yama", "bpf"]
        )


def test_already_armed_does_not_mutate() -> None:
    with tempfile.TemporaryDirectory() as raw:
        result, _state, calls = run_helper(
            Path(raw),
            "lockdown,capability,bpf",
            "quiet lsm=lockdown,capability,bpf\n",
        )
        assert result.returncode == 0, result.stderr
        assert "already armed" in result.stdout
        assert calls_text(calls) == ""


def test_second_run_does_not_duplicate_lsm_kargs() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        first, state, calls = run_helper(tmp, "lockdown,capability", "quiet\n")
        assert first.returncode == 0, first.stderr

        env = os.environ.copy()
        env.update(
            {
                "JINNGUARD_OSTREE_BOOTED_PATH": str(tmp / "ostree-booted"),
                "JINNGUARD_LSM_PATH": str(tmp / "lsm"),
                "JINNGUARD_RPM_OSTREE": str(tmp / "rpm-ostree"),
            }
        )
        second = subprocess.run(
            [str(SCRIPT)],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert second.returncode == 0, second.stderr
        assert "already armed" in second.stdout
        assert calls_text(calls).count("--append=lsm=") == 1
        assert calls_text(calls).count("--replace=lsm=") == 0
        assert state.read_text(encoding="utf-8").count("lsm=") == 1


def main() -> None:
    tests = [
        test_non_ostree_noop,
        test_append_preserves_live_lsm_modules,
        test_replace_preserves_live_lsm_modules,
        test_already_armed_does_not_mutate,
        test_second_run_does_not_duplicate_lsm_kargs,
    ]
    for test in tests:
        test()
        print(f"ok - {test.__name__}")


if __name__ == "__main__":
    main()
