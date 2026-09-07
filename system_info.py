#!/usr/bin/env python3
"""Portable, dependency-free, read-only Linux runtime inspector."""

from __future__ import annotations

import datetime
import getpass
import locale
import math
import os
import platform
import re
import resource
import shutil
import signal
import socket
import sys
import site
import threading
import time
from pathlib import Path
from typing import Any, Callable

UNKNOWN = "Unknown / Not exposed"
UNLIMITED = "Unlimited / No enforced limit"
SAFE_ENV_NAMES = {
    "PORT", "RENDER", "RENDER_CPU_COUNT", "RENDER_SERVICE_NAME", "RENDER_SERVICE_TYPE",
    "RENDER_REGION", "RENDER_GIT_BRANCH", "RENDER_GIT_COMMIT", "AWS_REGION",
    "AWS_EXECUTION_ENV", "AWS_LAMBDA_FUNCTION_NAME", "ECS_CONTAINER_METADATA_URI_V4",
    "ECS_CONTAINER_METADATA_URI", "KUBERNETES_SERVICE_HOST", "K_SERVICE", "K_REVISION",
    "DYNO", "HEROKU_APP_NAME", "VERCEL", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME",
    "GITHUB_ACTIONS", "CI", "NETLIFY", "CODEBUILD_BUILD_ARN",
}
SECRET_RE = re.compile(r"SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|APIKEY|AUTH|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL|DATABASE[_-]?URL|CONNECTION[_-]?STRING|JWT|COOKIE|SESSION|CERT|SSH", re.I)


def safe(fn: Callable[[], Any], default: Any = UNKNOWN) -> Any:
    try:
        return fn()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return default


def read(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def first(path: str | Path) -> str | None:
    text = read(path)
    return text.splitlines()[0].strip() if text and text.splitlines() else None


def integer(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return None


def number(value: Any) -> float | None:
    try:
        n = float(str(value).strip())
        return n if math.isfinite(n) else None
    except (TypeError, ValueError, OverflowError):
        return None


def bytes_text(value: int | float | None) -> str:
    if value is None or value < 0:
        return UNKNOWN
    n = float(value)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.1f} {units[i]} ({int(value):,} bytes)"


def limit_text(raw: str | None, count: bool = False) -> str:
    if raw is None:
        return UNKNOWN
    if raw.strip().lower() in {"max", "unlimited", "none", "-1"}:
        return UNLIMITED
    value = integer(raw)
    if value is None or value < 0:
        return UNKNOWN
    return f"{value:,} processes" if count else bytes_text(value)


def cpu_set(raw: str | None) -> list[int]:
    out: list[int] = []
    if not raw:
        return out
    for part in raw.split(","):
        try:
            if "-" in part:
                a, b = (int(x) for x in part.split("-", 1))
                if 0 <= a <= b:
                    out.extend(range(a, b + 1))
            else:
                x = int(part)
                if x >= 0:
                    out.append(x)
        except ValueError:
            continue
    return sorted(set(out))


def cpu_records() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in (read("/proc/cpuinfo") or "").splitlines() + [""]:
        if not line.strip():
            if current:
                records.append(current)
                current = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            current[k.strip().lower()] = v.strip()
    return records


def mounts() -> list[tuple[str, str, str, str]]:
    out = []
    for line in (read("/proc/mounts") or "").splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append((f[0], f[1], f[2], f[3]))
    return out


def cgroup_info() -> tuple[str, Path | None, dict[str, Path], str]:
    unified = None
    controllers: dict[str, Path] = {}
    ignored = {"rw", "ro", "relatime", "nosuid", "nodev", "noexec", "seclabel"}
    for _, mount, fs, opts in mounts():
        if fs == "cgroup2":
            unified = Path(mount)
        elif fs == "cgroup":
            for option in opts.split(","):
                if option not in ignored and not option.startswith("name="):
                    controllers.setdefault(option, Path(mount))
    relative = "/"
    for line in (read("/proc/self/cgroup") or "").splitlines():
        f = line.split(":", 2)
        if len(f) == 3 and f[2]:
            relative = f[2]
            break
    version = "v2" if unified else ("v1" if controllers else UNKNOWN)
    return version, unified, controllers, relative


def cg_read(names: tuple[str, ...], unified: Path | None, controllers: dict[str, Path], relative: str) -> str | None:
    rel = relative.lstrip("/")
    for name in names:
        if unified:
            value = first(unified / rel / name)
            if value is not None:
                return value
        for mount in controllers.values():
            value = first(mount / rel / name)
            if value is not None:
                return value
    return None


def parse_meminfo() -> dict[str, int]:
    out = {}
    for line in (read("/proc/meminfo") or "").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        f = rest.split()
        n = integer(f[0]) if f else None
        if n is not None:
            out[key] = n * 1024 if len(f) > 1 and f[1].lower() == "kb" else n
    return out


def provider() -> tuple[str, str, str]:
    e = os.environ
    if e.get("RENDER", "").lower() == "true" or e.get("RENDER_SERVICE_NAME") or e.get("RENDER_SERVICE_ID"):
        return "Render", "HIGH", "explicit Render environment variables"
    if e.get("AWS_EXECUTION_ENV", "").upper() == "AWS_ECS_FARGATE":
        return "AWS ECS/Fargate", "HIGH", "AWS_EXECUTION_ENV=AWS_ECS_FARGATE"
    if e.get("ECS_CONTAINER_METADATA_URI_V4") or e.get("ECS_CONTAINER_METADATA_URI"):
        return "AWS ECS", "HIGH", "explicit ECS metadata environment variable"
    if e.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "AWS Lambda", "HIGH", "AWS_LAMBDA_FUNCTION_NAME"
    if e.get("KUBERNETES_SERVICE_HOST"):
        return "Kubernetes", "HIGH", "KUBERNETES_SERVICE_HOST"
    if e.get("K_SERVICE") or e.get("K_REVISION"):
        return "Google Cloud Run", "HIGH", "explicit Cloud Run environment variables"
    if e.get("DYNO") or e.get("HEROKU_APP_NAME"):
        return "Heroku", "HIGH", "explicit Heroku environment variables"
    if e.get("VERCEL"):
        return "Vercel", "HIGH", "VERCEL"
    if e.get("RAILWAY_ENVIRONMENT"):
        return "Railway", "HIGH", "RAILWAY_ENVIRONMENT"
    if e.get("FLY_APP_NAME"):
        return "Fly.io", "HIGH", "FLY_APP_NAME"
    return "Unknown", "UNKNOWN", UNKNOWN


def container(version: str, unified: Path | None) -> tuple[str, str, str]:
    evidence: list[str] = []
    if Path("/.dockerenv").is_file(): evidence.append("/.dockerenv")
    if Path("/run/.containerenv").is_file(): evidence.append("/run/.containerenv")
    for p in ("/proc/1/cgroup", "/proc/self/cgroup"):
        text = (read(p) or "").lower()
        if any(x in text for x in ("docker", "containerd", "kubepods", "libpod", "lxc")):
            evidence.append(f"container marker in {p}")
    if os.environ.get("KUBERNETES_SERVICE_HOST"): evidence.append("KUBERNETES_SERVICE_HOST")
    if os.environ.get("ECS_CONTAINER_METADATA_URI_V4") or os.environ.get("ECS_CONTAINER_METADATA_URI"): evidence.append("ECS metadata environment variable")
    if len(evidence) >= 2: return "Yes", "HIGH", "; ".join(evidence)
    if len(evidence) == 1: return "Yes", "MEDIUM", evidence[0]
    if version in {"v1", "v2"} and unified: return "Unknown / conflicting evidence", "LOW", "cgroup exposed but no independent container marker"
    return "Unknown", "UNKNOWN", UNKNOWN


def virtualization() -> tuple[str, str, str]:
    product = first("/sys/class/dmi/id/product_name") or ""
    vendor = first("/sys/class/dmi/id/sys_vendor") or ""
    marker = f"{product} {vendor}".lower()
    if Path("/.dockerenv").is_file() or Path("/run/.containerenv").is_file(): return "Container", "HIGH", "container marker file"
    if any(x in marker for x in ("kvm", "qemu", "virtualbox", "vmware", "microsoft corporation")):
        return "Virtual machine", "MEDIUM", f"DMI product/vendor: {product or vendor}"
    if marker: return "Unknown", "LOW", f"DMI product/vendor: {product or vendor}"
    return UNKNOWN, "UNKNOWN", UNKNOWN


def env_values() -> list[str]:
    out = []
    for name, value in sorted(os.environ.items()):
        if name not in SAFE_ENV_NAMES or SECRET_RE.search(name):
            continue
        out.append(f"{name}={value[:197] + '...' if len(value) > 200 else value}")
    return out


def item(label: str, value: Any) -> None:
    if value is None or value == "": value = UNKNOWN
    print(f"{label:<34} {value}")


def section(title: str) -> None:
    print(f"\n{'=' * 16} {title} {'=' * 16}")


def collect() -> None:
    print("SYSTEM CONFIGURATION INSPECTOR")
    print("Read-only inspection using Python standard library; no external network calls.")
    cg = safe(cgroup_info, (UNKNOWN, None, {}, "/"))
    version, unified, controllers, relative = cg

    section("SYSTEM")
    os_release = {}
    for line in (read("/etc/os-release") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1); os_release[k] = v.strip().strip('"')
    item("OS", platform.system())
    item("Linux distribution", os_release.get("PRETTY_NAME") or os_release.get("NAME"))
    item("Distribution version", os_release.get("VERSION_ID") or os_release.get("VERSION"))
    item("Kernel version", platform.version()); item("Kernel release", platform.release()); item("Kernel build", platform.platform())
    item("Machine architecture", platform.machine()); item("CPU architecture", platform.uname().machine); item("Hostname", socket.gethostname())
    uptime = number((first("/proc/uptime") or "").split()[0])
    item("Uptime", f"{int(uptime // 86400)}d {int(uptime % 86400 // 3600)}h {int(uptime % 3600 // 60)}m {int(uptime % 60)}s" if uptime is not None else UNKNOWN)
    item("Boot time", datetime.datetime.fromtimestamp(time.time() - uptime).isoformat() if uptime is not None else UNKNOWN)
    item("Timezone", time.tzname[0]); item("Locale", safe(lambda: locale.setlocale(locale.LC_ALL)))
    v, conf, ev = safe(virtualization, (UNKNOWN, "UNKNOWN", UNKNOWN)); item("Virtualization", f"{v} (confidence={conf}; evidence={ev})")
    item("Init system", first("/proc/1/comm")); item("systemd presence", "Present" if Path("/run/systemd/system").exists() else "Not detected")
    item("Root filesystem", "/"); item("Current user", safe(getpass.getuser)); item("Shell", os.environ.get("SHELL", UNKNOWN))

    section("CPU")
    records = cpu_records(); rec = records[0] if records else {}
    model = rec.get("model name") or rec.get("hardware") or rec.get("cpu model")
    if not model or model.isdigit(): model = safe(platform.processor)
    if not model or str(model).isdigit(): model = UNKNOWN
    vendor = rec.get("vendor_id") or rec.get("vendor") or rec.get("cpu implementer") or UNKNOWN
    visible = safe(os.cpu_count); online_raw = first("/sys/devices/system/cpu/online"); online_set = cpu_set(online_raw)
    online = len(online_set) if online_set else visible
    offline = max(0, visible - online) if isinstance(visible, int) and isinstance(online, int) else UNKNOWN
    physical_ids = {r.get("physical id") for r in records if r.get("physical id")}
    item("CPU model", model); item("CPU vendor", vendor); item("Visible logical CPUs", visible); item("Online CPU count", online); item("Offline CPU count", offline)
    item("CPU architecture", platform.machine()); item("Physical CPU count", len(physical_ids) if physical_ids else UNKNOWN)
    item("Cores per socket", rec.get("cpu cores") or UNKNOWN); item("Threads per core", rec.get("siblings") or UNKNOWN)
    mhz = number(rec.get("cpu mhz")); item("CPU frequency", f"{mhz:.0f} MHz" if mhz is not None else UNKNOWN)
    item("CPU flags", rec.get("flags") or rec.get("features") or UNKNOWN)
    try: affinity = ",".join(map(str, sorted(os.sched_getaffinity(0))))
    except (AttributeError, OSError): affinity = UNKNOWN
    item("CPU affinity", affinity)
    if version == "v2": raw = cg_read(("cpu.max",), unified, controllers, relative); weight = cg_read(("cpu.weight",), unified, controllers, relative)
    else: raw = cg_read(("cpu.cfs_quota_us",), unified, controllers, relative); weight = cg_read(("cpu.shares",), unified, controllers, relative)
    if version == "v2" and raw:
        f = raw.split(); quota = f[0] if f else None; period = integer(f[1]) if len(f) > 1 else None
    else: quota = raw; period = integer(cg_read(("cpu.cfs_period_us",), unified, controllers, relative))
    item("CPU quota", UNLIMITED if quota in {"max", "-1"} else (f"{quota} µs" if quota else UNKNOWN)); item("CPU period", f"{period} µs" if period else UNKNOWN)
    qn = integer(quota); vcpu = qn / period if qn is not None and qn >= 0 and period else None
    item("Allocated CPU", f"{vcpu:.2f} vCPU" if vcpu is not None else (UNLIMITED if quota in {"max", "-1"} else UNKNOWN)); item("CPU weight / shares", weight or UNKNOWN)
    item("Effective CPU set", cg_read(("cpuset.cpus.effective", "cpuset.cpus"), unified, controllers, relative) or UNKNOWN)
    render_cpu = os.environ.get("RENDER_CPU_COUNT"); item("Provider-reported CPU allocation", f"{render_cpu} vCPU (Render)" if render_cpu else UNKNOWN)

    section("MEMORY")
    mem = parse_meminfo(); total = mem.get("MemTotal"); avail = mem.get("MemAvailable"); swap_total = mem.get("SwapTotal"); swap_free = mem.get("SwapFree")
    item("Host-visible memory", bytes_text(total)); item("Available memory", bytes_text(avail)); item("Used visible memory", bytes_text(total-avail if total is not None and avail is not None else None)); item("Free memory", bytes_text(mem.get("MemFree")))
    item("Buffers", bytes_text(mem.get("Buffers"))); item("Cached", bytes_text(mem.get("Cached")))
    mem_limit = cg_read(("memory.max", "memory.limit_in_bytes"), unified, controllers, relative); item("Memory allocation / limit", limit_text(mem_limit)); item("Memory max", limit_text(mem_limit))
    cur = cg_read(("memory.current", "memory.usage_in_bytes"), unified, controllers, relative); item("cgroup memory current", bytes_text(integer(cur))); item("cgroup memory high", limit_text(cg_read(("memory.high",), unified, controllers, relative)))
    item("cgroup memory swap max", limit_text(cg_read(("memory.swap.max", "memory.memsw.limit_in_bytes"), unified, controllers, relative))); item("Swap total", bytes_text(swap_total)); item("Swap free", bytes_text(swap_free)); item("Swap used", bytes_text(swap_total-swap_free if swap_total is not None and swap_free is not None else None))
    item("Memory pressure", (read("/proc/pressure/memory") or UNKNOWN).replace("\n", "; ")); item("cgroup memory events", (read("/sys/fs/cgroup/memory.events") or UNKNOWN).replace("\n", "; "))

    section("STORAGE")
    try: du = shutil.disk_usage("/"); total_d, used_d, free_d = du.total, du.used, du.free
    except OSError: total_d = used_d = free_d = None
    item("Visible root filesystem total", bytes_text(total_d)); item("Visible root filesystem used", bytes_text(used_d)); item("Visible root filesystem free", bytes_text(free_d))
    root = next((x for x in mounts() if x[1] == "/"), None); item("Filesystem type", root[2] if root else UNKNOWN); item("Mount point/source", f"{root[0]} on /" if root else UNKNOWN); item("Mount options", root[3] if root else UNKNOWN); item("Read-only filesystem", "Yes" if root and "ro" in root[3].split(",") else "No" if root else UNKNOWN)
    try: st = os.statvfs("/"); item("Inodes total", st.f_files); item("Inodes used", st.f_files-st.f_ffree); item("Inodes free", st.f_ffree)
    except OSError: item("Inodes total", UNKNOWN); item("Inodes used", UNKNOWN); item("Inodes free", UNKNOWN)
    item("Root filesystem writable", "Yes" if safe(lambda: os.access("/", os.W_OK), False) else "No")
    item("Filesystem list", "; ".join(f"{fs}:{mnt}" for _, mnt, fs, _ in mounts()[:30]) or UNKNOWN); item("Block devices", "; ".join(sorted(os.listdir("/sys/class/block"))) if Path("/sys/class/block").exists() else UNKNOWN); item("Provider-reported disk allocation", UNKNOWN)

    section("CONTAINER / CGROUP")
    c, cc, ce = container(version, unified); item("Container", c); item("Confidence", cc); item("Evidence", ce); item("cgroup version", version); item("cgroup path", relative)
    item("Exposed controllers", ", ".join(sorted(controllers)) if version == "v1" else (first(unified / "cgroup.controllers") if unified else UNKNOWN))
    item("PID limit", limit_text(cg_read(("pids.max",), unified, controllers, relative), True)); item("PID current", cg_read(("pids.current",), unified, controllers, relative) or UNKNOWN)
    io_max = read((unified / relative.lstrip("/") / "io.max") if unified else "") if version == "v2" else None; item("I/O limit information", (io_max or UNKNOWN).replace("\n", "; "))

    section("NAMESPACES")
    for name in ("pid", "mnt", "net", "ipc", "uts", "user", "cgroup"): item(f"{name} namespace", safe(lambda n=name: os.readlink(f"/proc/self/ns/{n}")))

    section("PROCESS")
    status = {}
    for line in (read("/proc/self/status") or "").splitlines():
        if ":" in line: k, v0 = line.split(":", 1); status[k] = v0.strip()
    item("Current PID", os.getpid()); stat = (first("/proc/self/stat") or "").split(); item("Parent PID", integer(stat[3]) if len(stat) > 3 else UNKNOWN); item("Process name", status.get("Name")); item("Executable", safe(lambda: os.readlink("/proc/self/exe"))); item("Command line", " ".join((read("/proc/self/cmdline") or "").split("\0")[:-1]) or UNKNOWN)
    item("Effective UID", os.geteuid()); item("Effective GID", os.getegid()); item("Username", safe(getpass.getuser)); item("Groups", os.getgroups()); item("Thread count", status.get("Threads"))
    limits = read("/proc/self/limits") or ""; nofile = next((x for x in limits.splitlines() if x.startswith("Max open files")), None); nproc = next((x for x in limits.splitlines() if x.startswith("Max processes")), None); item("Open-file limits", " ".join(nofile.split()[3:5]) if nofile else UNKNOWN); item("Process/PID limits", " ".join(nproc.split()[2:4]) if nproc else UNKNOWN); item("Current process status", status.get("State"))

    section("NETWORK")
    item("Hostname", socket.gethostname()); interfaces=[]
    try: names=[n for _, n in socket.if_nameindex()]
    except OSError: names=[]
    for n in sorted(names): interfaces.append(f"{n} (state={first(f'/sys/class/net/{n}/operstate') or UNKNOWN}, MAC={first(f'/sys/class/net/{n}/address') or UNKNOWN}, MTU={first(f'/sys/class/net/{n}/mtu') or UNKNOWN})")
    item("Interfaces", "; ".join(interfaces) or UNKNOWN)
    route_lines=[x for x in (read("/proc/net/route") or "").splitlines()[1:] if x.strip()]; item("Routes", f"{len(route_lines)} visible route(s)"); default=next((x.split()[0] for x in route_lines if len(x.split()) > 1 and x.split()[1] == "00000000"), None); item("Default route", f"interface {default}" if default else UNKNOWN)
    dns=[x.split()[1] for x in (read("/etc/resolv.conf") or "").splitlines() if x.startswith("nameserver ") and len(x.split()) > 1]; item("DNS configuration", f"{len(dns)} nameserver(s) configured" if dns else UNKNOWN); hosts=[x for x in (read("/etc/hosts") or "").splitlines() if x.strip() and not x.lstrip().startswith("#")]; item("/etc/hosts", f"{len(hosts)} entries visible"); item("IPv4/IPv6 addresses", UNKNOWN + " (local address enumeration not implemented; no external requests)")

    section("RUNTIME")
    item("Python version", platform.python_version()); item("Python implementation", platform.python_implementation()); item("Python executable", sys.executable); item("Python architecture", platform.architecture()[0]); item("Python compiler", platform.python_compiler()); item("Python build", " ".join(platform.python_build())); item("Current working directory", os.getcwd()); item("Python prefix", sys.prefix); item("Python base prefix", sys.base_prefix); item("Virtual environment", "Yes" if sys.prefix != sys.base_prefix else "No"); item("Site packages", "; ".join(safe(site.getsitepackages, [])) or UNKNOWN); item("sys.path entries", len(sys.path))

    section("RESOURCE ALLOCATION")
    item("Allocated CPU", f"{vcpu:.2f} vCPU" if vcpu is not None else (UNLIMITED if quota in {"max", "-1"} else UNKNOWN)); item("Memory allocation / limit", limit_text(mem_limit)); item("PID allocation / limit", limit_text(cg_read(("pids.max",), unified, controllers, relative), True)); item("Allocation source", f"cgroup {version}")

    section("RESOURCE LIMITS")
    rlimits = [("Open files", resource.RLIMIT_NOFILE), ("Processes", getattr(resource, "RLIMIT_NPROC", None)), ("Stack", resource.RLIMIT_STACK), ("Core dump", resource.RLIMIT_CORE), ("Locked memory", resource.RLIMIT_MEMLOCK), ("Address space", resource.RLIMIT_AS), ("File size", resource.RLIMIT_FSIZE)]
    for label, constant in rlimits:
        if constant is None: item(label, UNKNOWN); continue
        try:
            soft, hard = resource.getrlimit(constant); fmt=lambda x: "Unlimited" if x == resource.RLIM_INFINITY else str(x); item(label, f"{fmt(soft)} soft / {fmt(hard)} hard")
        except (ValueError, OSError): item(label, UNKNOWN)

    section("VIRTUALIZATION")
    item("Virtualization", f"{v} (confidence={conf}; evidence={ev})"); item("Confidence", conf); item("Evidence", ev)

    section("SECURITY")
    euid = safe(os.geteuid, -1); item("Root status", "Yes" if euid == 0 else "No" if euid >= 0 else UNKNOWN); item("Capabilities", status.get("CapEff", UNKNOWN)); item("No new privileges", status.get("NoNewPrivs", UNKNOWN)); item("Seccomp", status.get("Seccomp", UNKNOWN)); item("AppArmor", "Present" if Path("/sys/kernel/security/apparmor").exists() else UNKNOWN); item("SELinux", "Present" if Path("/sys/fs/selinux").exists() else UNKNOWN); item("Filesystem read-only status", "No" if root and "ro" not in root[3].split(",") else "Yes" if root else UNKNOWN)

    section("PLATFORM")
    pname, pconf, pevidence = provider(); item("Detected platform", pname); item("Confidence", pconf); item("Evidence", pevidence)

    section("SAFE ENVIRONMENT")
    vals=env_values()
    for x in vals: print(f"  {x}")
    if not vals: print(f"  {UNKNOWN}")
    print("  Secret-like and non-allowlisted environment variables are intentionally omitted.")
    print("\n[system-config-inspector] Inspection completed successfully.")


def serve() -> None:
    """Keep a deployment process alive without exposing a dashboard or API."""
    import http.server
    import socketserver
    port = integer(os.environ.get("PORT", "10000")) or 10000
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] == "/healthz":
                body=b"ok\n"; self.send_response(200)
            else:
                body=b"system-config-inspector is running; see deployment logs for the inspection report.\n"; self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *_: Any) -> None: return
    server=socketserver.TCPServer(("0.0.0.0", port), Handler)
    stopping=False
    def stop(signum: int, _frame: Any) -> None:
        nonlocal stopping
        if not stopping:
            stopping=True; print(f"\n[system-config-inspector] Shutdown signal {signum} received.", flush=True); threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    print(f"[system-config-inspector] Long-running mode: 0.0.0.0:{port} (health check only; no GUI/API).", flush=True)
    try: server.serve_forever(poll_interval=0.5)
    finally: server.server_close()


def main() -> int:
    mode = os.environ.get("INSPECTOR_MODE", "once").strip().lower()
    if "--serve" in sys.argv[1:]: mode="serve"
    if "--once" in sys.argv[1:]: mode="once"
    collect()
    if mode == "serve": serve()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
