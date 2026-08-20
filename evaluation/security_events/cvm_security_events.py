#!/usr/bin/env python3
"""Prepare and trigger harmless IMA security-event canaries on a CVM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


IMA_ROOT = Path("/sys/kernel/security/integrity/ima")
IMA_COUNT = IMA_ROOT / "runtime_measurements_count"
IMA_ASCII = IMA_ROOT / "ascii_runtime_measurements"
IMA_BINARY = IMA_ROOT / "binary_runtime_measurements"
DEFAULT_ROOT = Path("/opt/vordr-security-events")
STATE_SCHEMA = "vordr-security-events-cvm-v1"
SCENARIOS = (
    "no-update",
    "authorized-package",
    "shared-library-replacement",
    "kernel-module-insertion",
    "unauthorized-package",
    "binary-replacement",
)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=True,
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("run this command with sudo")


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command is missing: {name}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ima_count() -> int:
    return int(IMA_COUNT.read_text(encoding="ascii").strip())


def safe_slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-")
    if not value:
        raise ValueError("campaign must contain an alphanumeric character")
    return value[:40]


def assert_safe_campaign_root(path: Path) -> None:
    resolved = path.resolve()
    base = DEFAULT_ROOT.resolve()
    if resolved == base or base not in resolved.parents:
        raise RuntimeError(f"refusing unsafe campaign root: {resolved}")


def atomic_install(source: Path, destination: Path, mode: int = 0o755) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.new-{os.getpid()}")
    shutil.copyfile(source, temporary)
    os.chmod(temporary, mode)
    os.replace(temporary, destination)


def write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def compile_shared_library_trial(root: Path, trial: int) -> dict[str, Any]:
    build = root / "build" / "shared-library"
    target = root / "protected" / "shared-library"
    build.mkdir(parents=True)
    (target / "lib").mkdir(parents=True)

    safe_source = build / "safe.c"
    attack_source = build / "attack.c"
    app_source = build / "app.c"
    safe_source.write_text(
        f'const char *vordr_message(void) {{ return "approved-library-trial-{trial}"; }}\n',
        encoding="utf-8",
    )
    attack_source.write_text(
        f'const char *vordr_message(void) {{ return "trojan-canary-trial-{trial}"; }}\n',
        encoding="utf-8",
    )
    app_source.write_text(
        "#include <stdio.h>\n"
        "extern const char *vordr_message(void);\n"
        "int main(void) { puts(vordr_message()); return 0; }\n",
        encoding="utf-8",
    )

    safe_library = build / "libvordr-safe.so"
    attack_library = build / "libvordr-attack.so"
    app = build / "vordr-library-app"
    run(["gcc", "-shared", "-fPIC", str(safe_source), "-o", str(safe_library)])
    run(["gcc", "-shared", "-fPIC", str(attack_source), "-o", str(attack_library)])
    run(
        [
            "gcc",
            str(app_source),
            "-L",
            str(build),
            "-l:libvordr-safe.so",
            "-Wl,-rpath,$ORIGIN/lib",
            "-o",
            str(app),
        ]
    )

    target_app = target / "vordr-library-app"
    target_library = target / "lib" / "libvordr-safe.so"
    atomic_install(app, target_app)
    atomic_install(safe_library, target_library)
    run([str(target_app)])
    return {
        "trial": trial,
        "target_path": str(target_library),
        "trigger_path": str(target_app),
        "baseline_sha256": sha256_file(target_library),
        "candidate_path": str(attack_library),
        "candidate_sha256": sha256_file(attack_library),
        "event_aliases": [str(target_library), target_library.name],
    }


def compile_binary_trial(root: Path, trial: int) -> dict[str, Any]:
    build = root / "build" / "binary"
    target = root / "protected" / "binary" / f"vordr-canary-{trial}"
    build.mkdir(parents=True)
    safe_source = build / "safe.c"
    attack_source = build / "attack.c"
    safe_source.write_text(
        f'#include <stdio.h>\nint main(void) {{ puts("approved-binary-{trial}"); return 0; }}\n',
        encoding="utf-8",
    )
    attack_source.write_text(
        f'#include <stdio.h>\nint main(void) {{ puts("replaced-binary-{trial}"); return 0; }}\n',
        encoding="utf-8",
    )
    safe_binary = build / "safe"
    attack_binary = build / "attack"
    run(["gcc", str(safe_source), "-o", str(safe_binary)])
    run(["gcc", str(attack_source), "-o", str(attack_binary)])
    atomic_install(safe_binary, target)
    run([str(target)])
    return {
        "trial": trial,
        "target_path": str(target),
        "trigger_path": str(target),
        "baseline_sha256": sha256_file(target),
        "candidate_path": str(attack_binary),
        "candidate_sha256": sha256_file(attack_binary),
        "event_aliases": [str(target), target.name],
    }


def make_package_trial(
    root: Path,
    trial: int,
    campaign_tag: str,
    authorized: bool,
) -> dict[str, Any]:
    kind = "authorized" if authorized else "unauthorized"
    package_name = f"vordr-{kind}-{campaign_tag}-{trial}".lower()[:60]
    install_path = Path("/usr/local/bin") / package_name
    package_root = root / "build" / f"package-{kind}" / "root"
    control = package_root / "DEBIAN" / "control"
    payload = package_root / install_path.relative_to("/")
    control.parent.mkdir(parents=True)
    payload.parent.mkdir(parents=True)
    control.write_text(
        "\n".join(
            (
                f"Package: {package_name}",
                "Version: 1.0",
                "Section: utils",
                "Priority: optional",
                "Architecture: all",
                "Maintainer: Vordr Evaluation <vordr@example.invalid>",
                f"Description: harmless {kind} IMA experiment canary",
                "",
            )
        ),
        encoding="utf-8",
    )
    write_executable(
        payload,
        "#!/bin/sh\n"
        f"printf '%s\\n' 'vordr-{kind}-package-trial-{trial}'\n",
    )
    package_path = root / "build" / f"{package_name}.deb"
    run(["dpkg-deb", "--build", str(package_root), str(package_path)])
    return {
        "trial": trial,
        "package_name": package_name,
        "package_path": str(package_path),
        "target_path": str(install_path),
        "candidate_sha256": sha256_file(payload),
        "event_aliases": [str(install_path), install_path.name],
    }


def compile_module_trial(root: Path, trial: int, campaign_tag: str) -> dict[str, Any]:
    module_name = f"vprobe_{campaign_tag[:12]}_{trial}".lower().replace("-", "_")
    module_name = re.sub(r"[^a-z0-9_]", "_", module_name)[:48]
    build = root / "build" / "module"
    build.mkdir(parents=True)
    source = build / f"{module_name}.c"
    source.write_text(
        "#include <linux/init.h>\n"
        "#include <linux/module.h>\n"
        f'static int __init probe_init(void) {{ pr_info("Vordr harmless IMA probe {trial} loaded\\n"); return 0; }}\n'
        f'static void __exit probe_exit(void) {{ pr_info("Vordr harmless IMA probe {trial} unloaded\\n"); }}\n'
        "module_init(probe_init);\n"
        "module_exit(probe_exit);\n"
        'MODULE_LICENSE("GPL");\n'
        'MODULE_DESCRIPTION("Vordr harmless IMA security-event probe");\n',
        encoding="utf-8",
    )
    makefile = build / "Makefile"
    existing = makefile.read_text(encoding="utf-8") if makefile.exists() else ""
    makefile.write_text(existing + f"obj-m += {module_name}.o\n", encoding="utf-8")
    kernel_build = Path("/lib/modules") / os.uname().release / "build"
    run(["make", "-C", str(kernel_build), f"M={build}", "modules"])
    candidate = build / f"{module_name}.ko"
    target = root / "protected" / "module" / candidate.name
    return {
        "trial": trial,
        "module_name": module_name,
        "target_path": str(target),
        "candidate_path": str(candidate),
        "candidate_sha256": sha256_file(candidate),
        "event_aliases": [str(target), target.name, module_name],
    }


def preflight() -> dict[str, Any]:
    require_root()
    for command in ("gcc", "make", "dpkg-deb", "dpkg", "insmod", "rmmod"):
        require_command(command)
    kernel_build = Path("/lib/modules") / os.uname().release / "build"
    if not kernel_build.is_dir():
        raise RuntimeError(
            f"kernel headers are missing: {kernel_build}; install linux-headers-$(uname -r)"
        )
    for path in (IMA_COUNT, IMA_ASCII, IMA_BINARY):
        if not path.is_file() or not os.access(path, os.R_OK):
            raise RuntimeError(f"IMA interface is not readable by root: {path}")
    sig_enforce = Path("/sys/module/module/parameters/sig_enforce").read_text().strip()
    lockdown_path = Path("/sys/kernel/security/lockdown")
    lockdown = lockdown_path.read_text().strip() if lockdown_path.exists() else "unknown"
    return {
        "kernel": os.uname().release,
        "ima_count": ima_count(),
        "ima_policy_boot": (
            "tcb" if "ima_policy=tcb" in Path("/proc/cmdline").read_text() else "unknown"
        ),
        "module_sig_enforce": sig_enforce,
        "lockdown": lockdown,
        "kernel_headers": str(kernel_build),
    }


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    checks = preflight()
    campaign = safe_slug(args.campaign)
    campaign_root = (Path(args.root) / campaign).resolve()
    assert_safe_campaign_root(campaign_root)
    if campaign_root.exists():
        raise RuntimeError(
            f"campaign root already exists: {campaign_root}; choose a new campaign ID"
        )
    campaign_root.mkdir(parents=True)
    count_before = ima_count()
    shared: list[dict[str, Any]] = []
    binaries: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
    authorized_packages: list[dict[str, Any]] = []
    unauthorized_packages: list[dict[str, Any]] = []
    campaign_tag = re.sub(r"[^a-zA-Z0-9]", "", campaign).lower()[-12:] or "trial"

    for trial in range(1, args.trials + 1):
        trial_root = campaign_root / f"trial-{trial}"
        shared.append(compile_shared_library_trial(trial_root, trial))
        binaries.append(compile_binary_trial(trial_root, trial))
        modules.append(compile_module_trial(trial_root, trial, campaign_tag))
        authorized_packages.append(
            make_package_trial(trial_root, trial, campaign_tag, True)
        )
        unauthorized_packages.append(
            make_package_trial(trial_root, trial, campaign_tag, False)
        )

    state = {
        "schema": STATE_SCHEMA,
        "campaign_id": campaign,
        "campaign_root": str(campaign_root),
        "created_at": time.time(),
        "trials": args.trials,
        "ima_count_before_prepare": count_before,
        "ima_count_after_prepare": ima_count(),
        "preflight": checks,
        "artifacts": {
            "shared-library-replacement": shared,
            "binary-replacement": binaries,
            "kernel-module-insertion": modules,
            "authorized-package": authorized_packages,
            "unauthorized-package": unauthorized_packages,
        },
    }
    state_path = campaign_root / "state.json"
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    state_path.chmod(0o644)
    return {**state, "state_path": str(state_path)}


def load_state(path: Path) -> dict[str, Any]:
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("schema") != STATE_SCHEMA:
        raise ValueError(f"unsupported state schema in {path}")
    assert_safe_campaign_root(Path(state["campaign_root"]))
    return state


def artifact_for(state: dict[str, Any], scenario: str, trial: int) -> dict[str, Any]:
    artifacts = state.get("artifacts", {}).get(scenario, [])
    for artifact in artifacts:
        if int(artifact.get("trial", 0)) == trial:
            return artifact
    raise ValueError(f"no artifact for scenario={scenario}, trial={trial}")


def trigger(args: argparse.Namespace) -> dict[str, Any]:
    require_root()
    state_path = Path(args.state).resolve()
    state = load_state(state_path)
    if args.trial < 1 or args.trial > int(state["trials"]):
        raise ValueError(f"trial must be between 1 and {state['trials']}")

    records_dir = Path(state["campaign_root"]) / "records"
    records_dir.mkdir(exist_ok=True)
    record_path = records_dir / f"{args.scenario}-trial-{args.trial}.json"
    if record_path.exists() and not args.allow_repeat:
        raise RuntimeError(f"trial was already triggered: {record_path}")

    count_before = ima_count()
    started_at = time.time()
    artifact: dict[str, Any] = {}
    action_output = ""

    if args.scenario == "no-update":
        time.sleep(args.no_update_wait_s)
    else:
        artifact = artifact_for(state, args.scenario, args.trial)
        if args.scenario in {"authorized-package", "unauthorized-package"}:
            completed = run(["dpkg", "-i", artifact["package_path"]])
            action_output = completed.stdout + completed.stderr
            run([artifact["target_path"]])
        elif args.scenario == "shared-library-replacement":
            atomic_install(Path(artifact["candidate_path"]), Path(artifact["target_path"]))
            completed = run([artifact["trigger_path"]])
            action_output = completed.stdout + completed.stderr
        elif args.scenario == "binary-replacement":
            atomic_install(Path(artifact["candidate_path"]), Path(artifact["target_path"]))
            completed = run([artifact["trigger_path"]])
            action_output = completed.stdout + completed.stderr
        elif args.scenario == "kernel-module-insertion":
            target = Path(artifact["target_path"])
            atomic_install(Path(artifact["candidate_path"]), target, 0o644)
            completed = run(["insmod", str(target)])
            action_output = completed.stdout + completed.stderr
            time.sleep(0.2)
            run(["rmmod", artifact["module_name"]])
        else:  # pragma: no cover - argparse enforces choices
            raise ValueError(f"unsupported scenario: {args.scenario}")

    completed_at = time.time()
    record = {
        "schema": "vordr-security-event-trigger-v1",
        "campaign_id": state["campaign_id"],
        "scenario": args.scenario,
        "trial": args.trial,
        "attack_started_at": started_at,
        "trigger_completed_at": completed_at,
        "ima_count_before": count_before,
        "ima_count_after": ima_count(),
        "target_path": artifact.get("target_path", ""),
        "event_aliases": artifact.get("event_aliases", []),
        "baseline_sha256": artifact.get("baseline_sha256", ""),
        "candidate_sha256": artifact.get("candidate_sha256", ""),
        "package_name": artifact.get("package_name", ""),
        "module_name": artifact.get("module_name", ""),
        "action_output": action_output[-2000:],
    }
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--campaign", required=True)
    prepare_parser.add_argument("--trials", type=int, default=3)
    prepare_parser.add_argument("--root", default=str(DEFAULT_ROOT))

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--state", required=True)
    run_parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    run_parser.add_argument("--trial", type=int, required=True)
    run_parser.add_argument("--no-update-wait-s", type=float, default=0.2)
    run_parser.add_argument("--allow-repeat", action="store_true")

    args = parser.parse_args()
    try:
        if args.command == "preflight":
            result = preflight()
        elif args.command == "prepare":
            if args.trials <= 0:
                parser.error("--trials must be positive")
            result = prepare(args)
        else:
            result = trigger(args)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        detail = str(exc)
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (
                f"{exc}; stdout={exc.stdout[-1000:]}; stderr={exc.stderr[-1000:]}"
            )
        print(json.dumps({"status": "error", "error": detail}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
