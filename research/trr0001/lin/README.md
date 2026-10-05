# TRR0001 — Network Sniffing on Linux (T1040)

- **TRR ID:** TRR0001
- **Platform:** Linux (`lin`)
- **ATT&CK technique:** [T1040 — Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- **Status:** pilot — fully realized
- **Author:** det-eng
- **Date:** 2026/10/05

> This report uses Simplified Technical English (ASD-STE100) where practical.
> Syscall names, CVE identifiers, and kernel symbols are technical names.

## Summary

Network sniffing on Linux starts with a small number of rare syscalls. A
process opens a special socket, and sometimes it sets a packet ring or turns
on promiscuous mode. The socket call is the first and most reliable signal.

This TRR covers four ways a process can open a sniffing surface. Each way is one
**procedure**. Each procedure has one behavioral atomic that emits the syscall
pattern and then stops before it captures traffic. Each procedure maps to one or
more detections that key on the auditd `SYSCALL` record.

The atomics do not run a real sniffer tool. They emit the **syscall telemetry**
only. This is the gap that Atomic Red Team does not fill: ART runs `tcpdump` or
similar and captures the **tool**, not the low-level **syscall**.

All four procedures are built.

## Scope

- **In scope:** the syscall entry points for packet capture — `AF_PACKET`
  (link layer), `AF_INET`/`AF_INET6` raw sockets (network layer), and `AF_XDP`
  (express data path). Also the promiscuous-mode and packet-ring enrichment
  signals (`setsockopt`, `ioctl`).
- **Out of scope:** full capture (no `bind()` to an interface, no receive
  loop), real exploits, and the tool-level tests that ART already ships.

## Available Emulation Tests

| Procedure | Name | Core syscall(s) | Atomic source | GUID | Built |
|-----------|------|-----------------|---------------|------|:-----:|
| TRR0001.LIN.A | AF_PACKET raw socket | `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` | [`atomics/T1040/src/afpacket_rawsocket_behavioral.c`](../../../atomics/T1040/src/afpacket_rawsocket_behavioral.c) | `f574984c-36b6-491e-9f58-02595096b4ec` | ✅ |
| TRR0001.LIN.B | AF_PACKET PACKET_RX_RING (TPACKET_V3) + mmap | `socket(AF_PACKET, …)` + `setsockopt(SOL_PACKET, PACKET_RX_RING, …)` + `mmap()` | [`atomics/T1040/src/afpacket_mmap_ring_behavioral.c`](../../../atomics/T1040/src/afpacket_mmap_ring_behavioral.c) | `bb783b5e-4c9b-47ab-a518-f629e28c6047` | ✅ |
| TRR0001.LIN.C | AF_INET raw socket | `socket(AF_INET, SOCK_RAW, IPPROTO_…)` | [`atomics/T1040/src/afinet_raw_socket_behavioral.c`](../../../atomics/T1040/src/afinet_raw_socket_behavioral.c) | `5b4f0616-52cf-46fe-93fd-a5c8d4ab0dd5` | ✅ |
| TRR0001.LIN.D | AF_XDP socket | `socket(AF_XDP, SOCK_RAW, 0)` (+ `bpf(BPF_PROG_LOAD)` in a real pipeline) | [`atomics/T1040/src/afxdp_socket_behavioral.c`](../../../atomics/T1040/src/afxdp_socket_behavioral.c) | `0a18da73-ee76-4b26-b185-1b30893d1c44` | ✅ |

Each atomic is `deteng_`-safe, stops before harm, tolerates `EPERM` (and
`EAFNOSUPPORT` for AF_XDP), and cleans up. Each YAML entry is in
[`atomics/T1040/T1040.yaml`](../../../atomics/T1040/T1040.yaml).

## Detection strategies

- **Strategy 1 — AF_PACKET socket family.** Key on `socket()` with domain
  `AF_PACKET` (arg `a0` = `0x11`). This is the strongest single signal for
  link-layer capture. It fires on both Procedure A and Procedure B, because
  Procedure B opens the same socket before it sets up the ring.
- **Strategy 2 — AF_INET/AF_INET6 raw socket.** Key on `socket()` with domain
  `AF_INET` (`0x2`) or `AF_INET6` (`0xa`) AND a `SOCK_RAW` type. Match the
  masked `SOCK_RAW` value (low bits `0x3`), and tolerate `SOCK_CLOEXEC`
  (`0x80000`) and `SOCK_NONBLOCK` (`0x800`). Do not require `a1 == 0x3` exactly.
  `ping` and `traceroute` use raw sockets, so this strategy depends on a process
  allowlist.
- **Strategy 3 — AF_XDP socket family.** Key on `socket()` with domain `AF_XDP`
  (`0x2c`). Correlate with the eBPF program-load signal (T1014) for a
  higher-confidence detection of an XDP capture or redirect pipeline.
- **Enrichment — promiscuous mode and packet ring.** The audit rules now log
  `setsockopt` and `ioctl`. This makes two more signals visible: the
  `PACKET_RX_RING` / `PACKET_ADD_MEMBERSHIP` (`PACKET_MR_PROMISC`) `setsockopt`
  calls, and the `SIOCSIFFLAGS` / `IFF_PROMISC` `ioctl`. Use them to separate a
  socket that is opened and closed from a true capture setup. These syscalls are
  high-volume; scope them down before you load them on a production fleet.

## Detections

| Strategy | Rule | Keys on | Covers | Level | Built |
|----------|------|---------|--------|-------|:-----:|
| 1 | [`detections/sigma/T1040/afpacket_raw_socket.yml`](../../../detections/sigma/T1040/afpacket_raw_socket.yml) | `socket` a0 `0x11` | A, B | medium | ✅ |
| 2 | [`detections/sigma/T1040/afinet_raw_socket.yml`](../../../detections/sigma/T1040/afinet_raw_socket.yml) | `socket` a0 ∈ {`0x2`,`0xa`}, masked `SOCK_RAW` type | C | medium | ✅ |
| 3 | [`detections/sigma/T1040/afxdp_socket.yml`](../../../detections/sigma/T1040/afxdp_socket.yml) | `socket` a0 `0x2c` | D | medium | ✅ |
| 3 (bpf half) | [`detections/sigma/T1014/bpf_prog_load.yml`](../../../detections/sigma/T1014/bpf_prog_load.yml) | `bpf(BPF_PROG_LOAD)` | D | — | ✅ |
| enrichment | [`detections/audit/atomic.rules`](../../../detections/audit/atomic.rules) (`setsockopt`, `ioctl`) | promiscuous mode / packet ring | B (and A, C, D context) | n/a | ✅ |

## Validate

The validator compiles each atomic, parses each paired Sigma rule, and (with
root + auditd) proves the rule's `SYSCALL` selection matches the audit events
the atomic emits. Each new (rule, atomic) pair for this TRR is in the
`MANIFEST` in [`detections/validate_detections.py`](../../../detections/validate_detections.py).

```
# Compile atomics and parse rules only — no auditd needed:
python3 detections/validate_detections.py --dry-run

# Real validation — needs root and a running auditd:
sudo python3 detections/validate_detections.py
```

## References

- `packet(7)`, `raw(7)`, `ip(7)`, `socket(2)`
- AF_XDP kernel documentation: <https://www.kernel.org/doc/html/latest/networking/af_xdp.html>
- CVE-2016-8655, CVE-2017-7308 — AF_PACKET ring privilege-escalation bugs
