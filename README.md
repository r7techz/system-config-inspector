# System Config Inspector

A lightweight, read-only **Universal Linux Environment Inspector** for containers, VPSs, VMs, bare metal, Kubernetes, Render, AWS ECS/Fargate, Docker and similar Linux runtimes.

It uses **Python standard library only**. Bash is used only for startup. There is no browser GUI, RDP, VNC, desktop environment, frontend framework, database, telemetry, cloud SDK, or external network dependency.

The inspector never invents values. When the runtime does not expose a metric it prints:

```text
Unknown / Not exposed
```

## Modes

### One-shot inspection

```bash
python system_info.py --once
```

Prints the complete report and exits.

### Long-running deployment mode

Some platforms such as Render Web Services require a process to keep listening. Use:

```bash
python system_info.py --serve
```

This mode performs the same inspection first, prints the report to deployment logs, then keeps a tiny HTTP listener alive on `0.0.0.0:$PORT` (fallback `10000`). It exposes only:

```text
GET /healthz -> 200 ok
```

There is **no GUI and no conventional application API**.

`INSPECTOR_MODE=once|serve` can select the mode. Command-line `--once` or `--serve` takes precedence.

## What it inspects

- **SYSTEM** — OS, distribution, kernel, architecture, hostname, uptime, boot time, timezone, locale, init/systemd, user and shell.
- **CPU** — model, vendor, architecture, logical/online/offline CPUs, topology, frequency, flags, affinity, quota, period, weight/shares, cpuset, calculated vCPU and provider-reported CPU where exposed.
- **MEMORY** — host-visible memory, available/used/free, buffers/cache, cgroup current/high/max, allocation/limit, swap and memory pressure/events.
- **STORAGE** — visible root filesystem capacity, usage, free space, filesystem type, mount information, options, read-only state, inodes, filesystems and block devices. Provider disk allocation is kept separate and is reported only when actually exposed.
- **CONTAINER / CGROUP** — container evidence, confidence, cgroup v1/v2, path, controllers, CPU/memory/PID/I/O limits.
- **NAMESPACES** — PID, mount, network, IPC, UTS, user and cgroup namespaces.
- **PROCESS** — PID/PPID, executable, command line, UID/GID, groups, threads, process state and process limits.
- **NETWORK** — local interfaces, state, MAC, MTU, routes, default route, DNS configuration and `/etc/hosts`. No external DNS/HTTP request is made.
- **RUNTIME** — Python version, implementation, executable, architecture, compiler, build, cwd, prefixes, virtualenv, site-packages and `sys.path` count.
- **RESOURCE ALLOCATION** — actual cgroup-enforced CPU, memory and PID allocation separated from host-visible resources.
- **RESOURCE LIMITS** — relevant process `RLIMIT_*` values.
- **VIRTUALIZATION** — local evidence and confidence; no guessing from hostnames/IPs/CPU models.
- **SECURITY** — root status, capabilities, no-new-privileges, seccomp, AppArmor, SELinux and filesystem read-only state.
- **PLATFORM** — strong provider detection with confidence and evidence.
- **SAFE ENVIRONMENT** — only explicitly allowlisted deployment metadata.

## Resource terminology

The inspector deliberately distinguishes:

1. **Host-visible resources** — what `/proc`, `/sys` or the mounted filesystem makes visible.
2. **Container-visible resources** — what the current namespace/container exposes.
3. **Enforced/allocated resources** — cgroup limits that actually constrain the process/container.
4. **Provider-reported resources** — explicit values supplied by a deployment platform.

For example, a container may see 30 GB of host memory while its cgroup limit is only 512 MB. Those values must never be presented as the same allocation.

Likewise, visible root filesystem capacity is **not automatically the provider's persistent-disk allocation**.

## Provider detection

Provider detection uses strong evidence instead of weak guesses. Examples include:

- Render: `RENDER=true` or explicit Render service variables.
- AWS ECS/Fargate: `AWS_EXECUTION_ENV=AWS_ECS_FARGATE`.
- AWS ECS: ECS metadata environment variables.
- Kubernetes: `KUBERNETES_SERVICE_HOST`.
- Cloud Run: `K_SERVICE` / `K_REVISION`.
- Railway, Fly.io, Vercel, Heroku and other supported platforms: explicit platform variables.

Hostnames, IP addresses, CPU model names, kernel strings and generic cloud-looking values are not sufficient provider evidence.

## cgroup and architecture support

The inspector supports both:

- cgroup v1
- cgroup v2

and common architectures including:

- x86_64 / amd64
- aarch64 / arm64
- other ARM variants where the runtime exposes the information.

An unavailable CPU model or topology value is never represented as a fake `0`.

## Security and privacy

The environment is **not** dumped wholesale. Only allowlisted deployment metadata is eligible for output. Secret-like names such as passwords, tokens, API keys, credentials, private keys, cookies, sessions, certificates and similar values are omitted.

The report ends with:

```text
Secret-like and non-allowlisted environment variables are intentionally omitted.
```

Collectors are isolated so a missing `/proc`, `/sys`, cgroup file, permission, kernel feature or provider variable cannot crash the whole inspection.

## Deployment

### Render Web Service

Use:

```text
Build Command: No build command required
Start Command: python system_info.py --serve
```

The service prints the complete inspection report to Render logs, binds to `0.0.0.0:$PORT`, remains alive, and responds to `/healthz`.

### Docker

```bash
docker build -t system-config-inspector .
docker run --rm system-config-inspector
```

For a long-running container:

```bash
docker run --rm -e INSPECTOR_MODE=serve -e PORT=10000 -p 10000:10000 system-config-inspector
```

### Native Linux / VPS / VM / bare metal

```bash
python3 system_info.py --once
```

or:

```bash
PORT=10000 python3 system_info.py --serve
```

### Kubernetes / ECS / Fargate

Run the inspector as the workload/container you want to inspect. It reports only resources visible and enforceable from that runtime. Provider allocation is shown only when reliable provider evidence is available.

## Validation

```bash
python3 -m py_compile system_info.py
bash -n start.sh
python3 system_info.py --once
```

For long-running mode:

```bash
PORT=10000 python3 system_info.py --serve
```

Then check:

```bash
curl -i http://127.0.0.1:10000/healthz
```

## Limitations

A container cannot necessarily see the physical host's complete hardware configuration. Provider disk allocation, physical CPU topology, security controls, IP addresses and other metrics may be intentionally hidden by the runtime. The correct output in those cases is `Unknown / Not exposed` rather than an estimate.
