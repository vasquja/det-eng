# Exploited Java Service Crash: HotSpot Fatal Error Log (Linux)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> CVE IDs, ATT&CK IDs, JVM flags and file names are technical names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9040 |
| External IDs | T1190, T1499.004 |
| Tactics      | Initial Access, Impact |
| Platforms    | Linux |
| Contributors | det-eng |
| Status       | experimental |

### Scope Statement

This TRR covers the **on-host trace of a crash in a Java service** that an
adversary causes when they exploit a memory-corruption bug in the HotSpot JVM.
The case that started it is CVE-2026-114938 ("Java4Shell"): an integer underflow
in the C2 JIT's Base64 decode intrinsic (x86-64, AVX-512 VBMI) that writes out of
bounds on the Java heap. CISA published an alert on 2026-11-17, and Oracle fixed
the bug in its November 2026 Critical Security Patch Update. A failed or partial
exploit of such a bug crashes the JVM. This report models that crash and builds
the proof loop for the one trace every crash leaves: HotSpot creates its fatal
error log, `hs_err_pid<pid>.log`.

The report does not model a successful exploit's later steps (a shell child of
`java`, a web shell, an outbound connection). Those are post-exploitation
techniques with their own telemetry. The report also does not cover the network
request that carries the exploit: that request is in a web or proxy log, not on
the host, and this repository has no web-log telemetry.

## Technique Overview

A public-facing Java service (an API gateway, an identity provider, an
application server) reads data that anyone on the internet can send. If the JVM
under that service has a memory-corruption bug, an adversary can send data that
corrupts the JVM's memory. The adversary wants code execution. An exploit of
this kind is hard to make reliable, so many attempts crash the process before
they succeed. Each crash stops the service, and a supervisor (systemd, a
container runtime) usually starts it again, so the adversary can try again.

A crash is therefore the most common trace of an attempt. It is also a denial of
service by itself. The defender rarely sees the exploit request in a host log,
but the JVM always records its own death in a file on disk.

## Technical Background

**HotSpot fatal error handling.** When the HotSpot JVM gets a fatal signal in
its own code or in JIT-compiled code (`SIGSEGV`, `SIGBUS`, `SIGILL`), or when
its own checks call a fatal error, it runs its error handler
(`VMError::report_and_die`). The handler writes a report and then ends the
process. The report holds the signal, the faulting frame, the compiled method,
the registers and the memory map. By default its name is
`hs_err_pid<pid>.log`. HotSpot creates it in the working directory of the
process. If it cannot create it there (no space, no permission), it creates it
in the temporary directory (`/tmp` on Linux). The product flag
`-XX:ErrorFile=<path>` sets another name or place, where `%p` is the process id.

**Why the C2 intrinsic matters.** A JIT intrinsic is a hand-written machine-code
version of a library method. C2 uses it in place of the Java bytecode once the
method is hot. A bug in an intrinsic is outside the Java memory-safety checks: a
bad length can write past a heap object. A heap write past an object usually
corrupts a header or a pointer, and the next garbage collection or access
dereferences it. The result is a `SIGSEGV` in compiled code or in the garbage
collector, and the fatal error log.

**The file is rare.** A healthy production JVM does not crash. Developers see
the file on test hosts, and a native library bug or bad hardware can also
cause it. On a server, a new fatal error log, and more so two of them in a short
time on the same host, is worth a look.

**Telemetry.** A file sensor records the create: an EDR file event, a
file-integrity monitor, or `auditd` with a watch on the directory (`-F dir=...
-F perm=wa`), whose `PATH` record has `nametype=CREATE`.
`detections/k8s/auditd_file_events.py` turns that record into a Sigma
`linux`/`file_event` record (`TargetFilename`, `Image`, `EventType`).

## Procedures

| ID | Title | Tactic | Entry point |
|----|-------|--------|-------------|
| TRR9040.LIN.A | JVM fatal error writes `hs_err_pid<pid>.log` | Initial Access, Impact | HotSpot error handler `open(O_CREAT)` of the fatal error log |

### Procedure A: JVM fatal error writes `hs_err_pid<pid>.log`  (`TRR9040.LIN.A`)

The adversary sends crafted input to a public-facing Java service. For
CVE-2026-114938 the input is Base64 text in a field the service decodes before
it authenticates the caller: an HTTP Basic `Authorization` header, a JWT, or a
SAML message. When the decode runs in the C2 intrinsic on a CPU with AVX-512
VBMI, the bad length writes past the heap object. The JVM then crashes, and
its error handler creates `hs_err_pid<pid>.log`.

- **Prerequisites:** network access to the service. No credentials. For
  CVE-2026-114938: an unpatched JDK on x86-64 with AVX-512 VBMI and the Base64
  intrinsic on (the default).
- **Impact:** the service stops (denial of service). A reliable exploit can give
  code execution as the service user; the crash is the trace of each attempt
  that fails.
- **Same procedure, other bugs:** every HotSpot memory-corruption crash takes
  this path to the same file, whatever bug or input caused it.

#### Detection Data Model — `TRR9040.LIN.A`

![DDM - JVM fatal error log](ddms/trr9040_lin_a.png)

Source: [`ddms/trr9040_lin_a.json`](ddms/trr9040_lin_a.json) (Arrows app format).

**DDM summary.** The shaded node is the create of `hs_err_pid<pid>.log` by the
crashing JVM, seen by a file sensor. It is the one node every crash reaches,
whatever the bug and the input. The earlier nodes (the request, the decode, the
signal) are not visible to a host file sensor. The restart of the service is
enrichment: a second crash on the same host soon after the first is the retry
pattern of an exploit.

## Detection Strategy

**Strategy 1 (chokepoint): the create of a fatal error log** — covers A.
Key on a file event whose `TargetFilename` contains `/hs_err_pid` and ends with
`.log`, with `EventType: create`. The rule does not key on the process image, so
a JVM under `jsvc`, a wrapper or a renamed launcher still matches. The create,
not a read or a rotation, is the crash; a log shipper that reads the file or
`logrotate` that compresses it does not match.
sensor: EDR / FIM file events, or `auditd` with a dir watch, converted by
`detections/k8s/auditd_file_events.py`.
rule: [`detections/sigma/T1190/linux_jvm_fatal_error_log_create.yml`](../../../detections/sigma/T1190/linux_jvm_fatal_error_log_create.yml)

**Enrichment (not required):** two or more creates on one host in 15 minutes
(the retry pattern); the vendor and version line inside the file; a `java`
process start right after the create (the supervisor's restart).

**Gaps.**
- A service started with `-XX:ErrorFile=<path>` that renames the file does not
  match. Add that name to the rule where a fleet uses it.
- A crash that cannot write the file (a read-only root file system with no
  writable `/tmp`) leaves no file. Container stdout still shows the fatal error
  header.
- The rule shows that a JVM crashed, not that an adversary caused it. The
  fatal error log (the problematic frame names the Base64 intrinsic stub) and
  the web log of the service tell an exploit from an ordinary crash.

| Procedure | Covered by | How | Status |
|-----------|-----------|-----|--------|
| A | Strategy 1 (chokepoint) | create of `hs_err_pid<pid>.log` | built + proven |

## Available Emulation Tests

| ID | Test | Status |
|----|------|--------|
| TRR9040.LIN.A | [`atomics/T1190/src/emulate.sh`](../../../atomics/T1190/src/emulate.sh) with [`Trr9040Crash.java`](../../../atomics/T1190/src/Trr9040Crash.java) (YAML: [`atomics/T1190/T1190.yaml`](../../../atomics/T1190/T1190.yaml)) | **built** |

The emulation is not an exploit. It runs a small Java program under a 16 MiB
heap with `-XX:+CrashOnOutOfMemoryError`, so the `OutOfMemoryError` becomes a
VM fatal error and HotSpot writes the same `hs_err_pid<pid>.log` as for a
`SIGSEGV`. It runs in a fixed work directory, `/tmp/trr9040-crash`, which CI
watches with `auditd`. `validate_apiserver_detections.py` gates the rule on the
JVM's own create in that directory, in the procedure's ledger window (`9040 A`,
source `file`). The kind node and the runner share one kernel and one `auditd`,
so the job's node file sensor records it; no Kubernetes object is involved.

## Detections

| Strategy | Covers | Sigma rule | Audit rule |
|----------|--------|------------|------------|
| 1 (chokepoint) | A | [`detections/sigma/T1190/linux_jvm_fatal_error_log_create.yml`](../../../detections/sigma/T1190/linux_jvm_fatal_error_log_create.yml) | `-F dir=/tmp/trr9040-crash -F perm=wa -F key=k8s_node_file` (CI); on a server, a watch on each Java service's working directory and `/tmp` |

## References

- CISA alert, 2026-11-17, CVE-2026-114938:
  <https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching>
- Oracle Critical Security Patch Update, November 2026:
  <https://www.oracle.com/security-alerts/cspunov2026.html>
- Oracle, Java SE 17 Troubleshooting Guide, "Location of Fatal Error Log":
  <https://docs.oracle.com/en/java/javase/17/troubleshoot/location-fatal-error-log.html>
- Oracle, Java SE 25 HotSpot VM guide, "Fatal Error Reporting":
  <https://docs.oracle.com/en/java/javase/25/vm/error-reporting.html>
- SigmaHQ `rules/application/jvm/java_rce_exploitation_attempt.yml` (nearest
  prior art; keys on application error-log keywords, not on the fatal error log).
- MITRE ATT&CK T1190 Exploit Public-Facing Application; T1499.004 Application or
  System Exploitation.
