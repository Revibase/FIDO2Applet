"""Resolve JC_HOME and a JPype-compatible JVM path for jcardsim."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from typing import Iterable, Optional, Sequence


def resolve_jc_home(repo_root: str) -> str:
    """JavaCard SDK directory (contains lib/ with api_classic.jar etc.)."""
    env = os.environ.get("JC_HOME")
    if env:
        path = env if os.path.isabs(env) else os.path.join(repo_root, env)
        lib = os.path.join(path, "lib")
        if os.path.isdir(lib):
            return os.path.abspath(path)
        raise ValueError(f"JC_HOME lib not found: {lib}")

    for candidate in (
        os.path.join(repo_root, "sdks", "jc305u4_kit"),
    ):
        if os.path.isdir(os.path.join(candidate, "lib")):
            return os.path.abspath(candidate)

    raise ValueError(
        "JC_HOME not set and no bundled JavaCard SDK found "
    )


def _jvm_library_candidates(java_home: str) -> list[str]:
    home = os.path.abspath(java_home)
    if sys.platform == "darwin":
        names = [
            os.path.join("lib", "server", "libjvm.dylib"),
            os.path.join("lib", "jli", "libjli.dylib"),
            os.path.join("lib", "libjli.dylib"),
            os.path.join("jre", "lib", "jli", "libjli.dylib"),
        ]
    elif os.name == "nt":
        names = [
            os.path.join("bin", "server", "jvm.dll"),
            os.path.join("jre", "bin", "server", "jvm.dll"),
        ]
    else:
        names = [
            os.path.join("lib", "server", "libjvm.so"),
            os.path.join("lib", "jli", "libjli.so"),
            os.path.join("jre", "lib", "amd64", "jli", "libjli.so"),
        ]
    return [os.path.join(home, rel) for rel in names]


def _loadable_jvm_library(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if sys.platform != "darwin":
        return True
    try:
        proc = subprocess.run(
            ["file", "-b", path],
            check=True,
            capture_output=True,
            text=True,
        )
        text = proc.stdout.lower()
        py = platform.machine().lower()
        if py in ("arm64", "aarch64"):
            return "arm64" in text
        if py in ("x86_64", "amd64"):
            return "x86_64" in text
    except (OSError, subprocess.CalledProcessError):
        return True
    return True


def _resolve_from_java_home(java_home: str) -> Optional[str]:
    if java_home.endswith((".dylib", ".so", ".dll")):
        return java_home if _loadable_jvm_library(java_home) else None
    for candidate in _jvm_library_candidates(java_home):
        if _loadable_jvm_library(candidate):
            return candidate
    return None


def _java_homes_to_try() -> Iterable[str]:
    explicit = os.environ.get("JPYPE_JVM")
    if explicit:
        yield explicit
        return

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        yield java_home

    if sys.platform == "darwin":
        for version in ("17", "11", ""):
            cmd = ["/usr/libexec/java_home"]
            if version:
                cmd.extend(["-v", version])
            try:
                proc = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                home = proc.stdout.strip()
                if home:
                    yield home
            except (OSError, subprocess.CalledProcessError):
                continue

    try:
        import jpype

        default = jpype.getDefaultJVMPath()
        if default:
            yield default
    except Exception:
        pass


def resolve_jvm_path() -> str:
    """
    Return a JVM library path JPype can load in this process.

    On Apple Silicon, arm64 Python cannot load x86_64 libjvm even if the file
    exists — run the process under ``arch -x86_64`` or install an arm64 JDK.
    """
    for java_home in _java_homes_to_try():
        if not java_home:
            continue
        resolved = _resolve_from_java_home(java_home)
        if resolved is not None:
            return resolved

    py_arch = platform.machine()
    raise RuntimeError(
        "No loadable JVM found for JPype. "
        f"Python is {py_arch}. Install a JDK (e.g. brew install openjdk@17), "
        "set JAVA_HOME to a matching architecture, or on Apple Silicon with an "
        "x86_64 JDK only, run:\n"
        "  arch -x86_64 ./scripts/run_python_tests.sh"
    )


def start_jvm(
    *jvm_args: str,
    classpath: Optional[Sequence[str]] = None,
) -> None:
    """Start JPype, preferring auto-detection and falling back to explicit path."""
    import jpype

    if jpype.isJVMStarted():
        return

    cp = list(classpath or [])
    try:
        jpype.startJVM(*jvm_args, classpath=cp)
        return
    except Exception:
        pass

    jvm_path = resolve_jvm_path()
    jpype.startJVM(jvm_path, *jvm_args, classpath=cp)


def jvm_path_loadable(jvm_path: Optional[str] = None) -> bool:
    """Probe whether JPype can start the given (or resolved) JVM."""
    import jpype

    if jpype.isJVMStarted():
        return True
    try:
        start_jvm(classpath=[])
        jpype.shutdownJVM()
        return True
    except Exception:
        if jvm_path is None:
            return False
        try:
            jpype.startJVM(jvm_path, classpath=[])
            jpype.shutdownJVM()
            return True
        except Exception:
            return False
