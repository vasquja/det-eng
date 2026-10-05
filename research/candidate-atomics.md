# Candidate Atomics — Research Backlog

Ten ideas for new behavioral atomic tests. None of these is in Atomic Red
Team (ART) or other well-known open-source atomic collections at the time of
writing. Each idea follows this repository's model: a small program emits the
rare, high-signal **syscall pattern** of an exploit or abuse primitive, then
stops **before** any harmful step. Each idea pairs with an auditd-based Sigma
rule, the same as the existing T1068 atomics.

> Text below uses Simplified Technical English (ASD-STE100) where practical.
> Syscall names, CVE identifiers, and kernel symbols are technical names.

## Why these are not covered

ART is procedure-level and Windows-heavy. On Linux, ART usually runs a real
tool (for example `tcpdump` or `insmod`) to complete a technique end to end.
ART rarely ships a **pure syscall-telemetry generator** that stops short of
harm. The ideas below target that gap. They also target modern kernel
interfaces (io_uring, eBPF, userfaultfd) that many sensors still do not watch.

**Before you build any idea, do the checklist step:** confirm the test is
still absent from the current ART index and from other public collections.

**Implemented so far:** #5 DirtyPipe (`atomics/T1068/`) and #10 AF_PACKET
(`atomics/T1040/`), each with a C source and a Sigma rule. The rest remain
open.

## Summary

| # | Title | ATT&CK | Core telemetry (benign stub) | Gap vs. ART |
|---|-------|--------|------------------------------|-------------|
| 1 | userfaultfd heap-grooming signature | T1068 | `userfaultfd()` + `UFFDIO_REGISTER` | No userfaultfd telemetry in ART |
| 2 | io_uring syscall-bypass signature | T1562.001 / T1068 | `io_uring_setup()` + `io_uring_enter()` | io_uring is an ART blind spot |
| 3 | eBPF program load from a shell | T1068 / T1562 | `bpf(BPF_PROG_LOAD)` + map create | No BPF_PROG_LOAD behavioral test |
| 4 | memfd fileless execution signature | T1620 / T1055 | `memfd_create()` + `fexecve()` | No clean memfd→fexecve generator |
| 5 | DirtyPipe splice precondition | T1068 (CVE-2022-0847) | `splice()` read-only fd → pipe | No DirtyPipe behavioral test |
| 6 | keyring stuffing signature | T1068 / T1556 | `add_key()` / `keyctl()` volume | No keyring telemetry in ART |
| 7 | PTRACE_TRACEME self-trace signature | T1622 / T1055.008 | `ptrace(PTRACE_TRACEME)` + exec | No TRACEME anti-analysis generator |
| 8 | setns host-namespace join | T1611 | `open(/proc/1/ns/*)` + `setns()` | T1611 coverage is Docker-API only |
| 9 | perf_event_open unusual-use | T1068 | `perf_event_open()` non-profiler | No perf_event_open telemetry |
| 10 | AF_PACKET raw socket signature | T1040 / T1068 | `socket(AF_PACKET, SOCK_RAW)` | ART uses tools, not the syscall |

---

## 1. userfaultfd heap-grooming signature

- **ATT&CK:** T1068 — Exploitation for Privilege Escalation
- **Description:** The test calls `userfaultfd()` and registers a memory
  region with `UFFDIO_REGISTER`. It starts a fault-handler thread. It then
  stops. It does not race any kernel object. userfaultfd lets an attacker
  pause the kernel in the middle of a copy. This is a common timing primitive
  for use-after-free and heap-spray exploits.
- **Why it is not covered:** ART has no userfaultfd test. Most normal software
  never calls `userfaultfd()`. The syscall alone is therefore a strong signal.
- **Reference / technique to explore:** `userfaultfd(2)`;
  `vm.unprivileged_userfaultfd` sysctl; many Linux LPE write-ups use
  userfaultfd to win a race window.

## 2. io_uring syscall-bypass signature

- **ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools; T1068
- **Description:** The test calls `io_uring_setup()` and submits a benign file
  read through `io_uring_enter()`. The read never passes through the classic
  `read()`/`openat()` syscalls. This shows how io_uring hides I/O from sensors
  that only hook traditional syscalls.
- **Why it is not covered:** ART has no io_uring content. Many EDR and auditd
  setups still do not see io_uring operations. The test makes the blind spot
  visible so a team can measure its own coverage.
- **Reference / technique to explore:** `io_uring_setup(2)`,
  `io_uring_enter(2)`; public research on io_uring as an EDR evasion surface.

## 3. eBPF program load from a shell

- **ATT&CK:** T1068; T1562 — Impair Defenses
- **Description:** The test calls `bpf(BPF_PROG_LOAD)` to load a tiny, harmless
  eBPF program (for example a no-op, or a read-only counter). It also creates a
  BPF map. The program does nothing and is unloaded at once. An eBPF rootkit or
  a BPF-based privesc begins with this same step.
- **Why it is not covered:** ART has no `BPF_PROG_LOAD` behavioral test. A
  program load from an interactive shell or an unexpected parent is unusual on
  most fleets and is a useful detection anchor.
- **Reference / technique to explore:** `bpf(2)`; open-source eBPF rootkits
  (TripleCross, boopkit, ebpfkit) all start with program and map creation.

## 4. memfd fileless execution signature

- **ATT&CK:** T1620 — Reflective Code Loading; T1055 — Process Injection
- **Description:** The test creates an anonymous file with `memfd_create()`,
  writes a tiny harmless ELF into it, and runs it with `fexecve()`. No file
  touches the disk. The running process shows a path like
  `/memfd:...(deleted)`, which is a clear artifact.
- **Why it is not covered:** ART has a little fileless content but no clean
  `memfd_create` → `fexecve` generator with detection guidance. Linux malware
  droppers use this pattern often.
- **Reference / technique to explore:** `memfd_create(2)`, `fexecve(3)`,
  `execveat(2)` with an empty path.

## 5. DirtyPipe splice precondition signature (CVE-2022-0847)

- **ATT&CK:** T1068 (CVE-2022-0847)
- **Description:** The test opens a read-only file, creates a pipe, and uses
  `splice()` to move bytes from the file into the pipe. This sets the pipe
  buffer merge flag, which is the exact DirtyPipe precondition. The test then
  stops. It never writes to the file.
- **Why it is not covered:** ART has no DirtyPipe behavioral test. A `splice()`
  from a read-only descriptor into a pipe, done by a normal user, is a tight
  signature. This idea also extends the repository's existing splice theme
  (CopyFail, DirtyFrag).
- **Reference / technique to explore:** Max Kellermann's CVE-2022-0847
  write-up; `splice(2)`; `PIPE_BUF_FLAG_CAN_MERGE`.

## 6. keyring stuffing signature

- **ATT&CK:** T1068; T1556 — Modify Authentication Process
- **Description:** The test uses `add_key()` and `keyctl()` to add many keys,
  or one large payload, to the session keyring. This mirrors the setup of
  several kernel keyring exploits. The test adds only harmless data and clears
  the keys on cleanup.
- **Why it is not covered:** ART has no keyring telemetry. Normal keyring
  traffic is low in volume, so a burst is easy to detect.
- **Reference / technique to explore:** `add_key(2)`, `keyctl(2)`;
  CVE-2016-0728 (keyring refcount), CVE-2022-1998.

## 7. PTRACE_TRACEME self-trace signature

- **ATT&CK:** T1622 — Debugger Evasion; T1055.008 — Ptrace System Calls
- **Description:** The test forks, calls `ptrace(PTRACE_TRACEME)` in the child,
  and then runs a harmless command. This is a common anti-debug trick and
  appears in some SUID privesc tricks. The test traces only itself.
- **Why it is not covered:** ART has ptrace **injection** content but no
  `PTRACE_TRACEME` self-trace or anti-analysis generator with detection notes.
- **Reference / technique to explore:** `ptrace(2)` `PTRACE_TRACEME`;
  `kernel.yama.ptrace_scope` sysctl; common anti-debug patterns.

## 8. setns host-namespace join (container escape telemetry)

- **ATT&CK:** T1611 — Escape to Host
- **Description:** The test opens a namespace file (for example
  `/proc/1/ns/mnt`) and calls `setns()` to try to join a host namespace. In a
  normal environment the call fails safely without privilege. The point is the
  **telemetry** of a container-escape primitive, not a real escape.
- **Why it is not covered:** ART's T1611 content is mostly Docker-API abuse. It
  has no clean `setns()` syscall generator. The `open` of `/proc/1/ns/*`
  followed by `setns()` is a strong escape indicator.
- **Reference / technique to explore:** `setns(2)`, `nsenter(1)`;
  CVE-2022-0492 (cgroups release_agent); runc escape write-ups.

## 9. perf_event_open unusual-use signature

- **ATT&CK:** T1068
- **Description:** The test calls `perf_event_open()` with a benign counter
  from a process that is not a profiler. Historically this syscall was a large
  LPE surface. The test opens and closes the event and does nothing else.
- **Why it is not covered:** ART has no `perf_event_open` telemetry. Outside
  profilers (`perf`, some APM agents) most hosts never see it.
- **Reference / technique to explore:** `perf_event_open(2)`; CVE-2013-2094
  (perf_swevent); `kernel.perf_event_paranoid` sysctl.

## 10. AF_PACKET raw socket signature

- **ATT&CK:** T1040 — Network Sniffing; T1068
- **Description:** The test creates a raw packet socket with
  `socket(AF_PACKET, SOCK_RAW, ...)`. It may set a benign ring version, then
  closes the socket. AF_PACKET both enables sniffing and has been a repeated
  kernel-exploit surface.
- **Why it is not covered:** ART's sniffing tests run `tcpdump` or similar.
  They capture the **tool**, not the **syscall**. A raw AF_PACKET socket from
  an unexpected process is a distinct, lower-level signal.
- **Reference / technique to explore:** `packet(7)`; CVE-2016-8655,
  CVE-2017-7308 (AF_PACKET ring exploits).

---

## Suggested build order (next few days)

1. **#5 DirtyPipe** and **#10 AF_PACKET** — closest to the existing splice and
   socket atomics; least new ground.
2. **#4 memfd** and **#8 setns** — small C programs, clear artifacts, easy to
   verify on a lab host.
3. **#1 userfaultfd**, **#3 eBPF**, **#9 perf_event_open** — modern, high-value
   telemetry; check kernel config and sysctl gates first.
4. **#2 io_uring**, **#6 keyring**, **#7 PTRACE_TRACEME** — useful for coverage
   gap measurement; plan the Sigma logsource carefully.

Each atomic needs: one C source file under `atomics/<Txxxx>/src/`, one entry in
the technique YAML, and one Sigma rule under `detections/sigma/<Txxxx>/`.
