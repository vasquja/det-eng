# Research — Technique Research Reports (TRRs)

This folder holds the research layer of the repository. Research comes first.
A Technique Research Report (TRR) is the start of each detection. The TRR
drives the emulation test and the detection rule. It does not come after them.

> Text in this folder uses Simplified Technical English (ASD-STE100) where
> practical. Syscall names, CVE identifiers, kernel symbols, and ATT&CK IDs
> are technical names and stay as they are.

## Why research-first

The rest of the repository used to start at a syscall primitive. You wrote an
atomic, then a rule. The research was not written down.

This layer inverts that order. You model the MITRE technique first. You list
its procedures. You find where to detect them. Only then do you build the test
and the rule. This is the Technique Research Report method from Andrew
VanVleet and the [tired-labs/techniques][tl] project.

[tl]: https://github.com/tired-labs/techniques

## The flow

```
0. Pick ONE MITRE technique for ONE platform.
1. RESEARCH (this folder): write the TRR.
     - Technique Overview      (plain language)
     - Technical Background     (mechanics, controls, why it works)
     - Procedures               (A, B, C ... = distinct execution paths)
     - Detection Data Model     (one graph per procedure)
     - Detection Strategy       (pick the invariant chokepoint that covers
                                 the MOST procedures; fall back to one rule
                                 per procedure only where no chokepoint exists)
2. EMULATE (../atomics):  one behavioral test per procedure.
3. DETECT  (../detections/sigma):  one Sigma rule per detection strategy.
4. PROVE   (../detections/validate_detections.py): atomic -> telemetry -> rule.
5. CONTRIBUTE upstream:
     - TRR   -> tired-labs/techniques
     - tests -> redcanaryco/atomic-red-team
     - rules -> SigmaHQ/sigma
```

## The procedure ID is the spine

Every artifact names the procedure it serves. The procedure ID ties the
research, the test, and the rule together.

Procedure ID format (VanVleet): `TRRID.PLATFORM.LETTER` — for example
`TRR9001.LIN.A`.

A procedure is a **distinct execution path**. The same path in a different
tool or a different language is the **same** procedure. For example, `tcpdump`
and a hand-written C sniffer both open an `AF_PACKET` socket; they are one
procedure, not two.

## The detection strategy idea (cover the most procedures)

Read the Detection Data Model for each procedure. Look for a node or an edge
that every procedure must pass through. This is an **invariant chokepoint** —
a condition the attacker cannot avoid, whatever tool they pick or how they
obfuscate it.

One rule at the chokepoint covers many procedures. This is the goal.
You write a per-procedure rule only for a procedure that the chokepoint does
not cover.

## Folder layout

The layout mirrors `tired-labs/techniques` so a TRR is ready to contribute.

```
research/
  README.md                 <- this file
  index.json                <- machine-readable index of the TRRs here
  candidate-atomics.md       <- backlog of future behavioral atomics
  templates/
    TRR-TEMPLATE.md          <- copy this to start a new TRR
    ddm-template.json        <- Arrows app JSON skeleton for a DDM
  tools/
    render_ddm.py            <- renders a DDM JSON to the PNG the TRR shows
  trrNNNN/
    <platform>/              <- platform code from tired-labs platforms.json
      README.md              <- the TRR (always README.md)
      ddms/                  <- Detection Data Models (Arrows JSON + rendered PNG)
      images/                <- other figures
```

Platform codes (from tired-labs `platforms.json`): `lin` Linux, `win` Windows,
`mac` macOS, `ad` Active Directory, `dkr` Docker, `k8s` Kubernetes, `aws`,
`azr`, `gcp`, `m365`, `and` Android, `ios`, `phy` Physical.

## TRR IDs here vs. upstream

This repository assigns its own local `TRRNNNN` IDs in the **`TRR9000+`
band** (the pilot is `TRR9001`). Upstream `tired-labs/techniques` assigns
IDs sequentially from the low numbers (its `TRR0001` is a reserved example;
real reports start higher and keep climbing), so the `9000+` band keeps a
local ID from ever colliding with a real upstream one, and it reads clearly
as "local, not an assigned upstream ID".

When you open a pull request to `tired-labs/techniques`, copy the folder to
`trr0000/` and use `TRR0000` in the text. The upstream maintainers assign the
final ID on merge.

## Index

| Local ID | ATT&CK | Technique | Platform | Folder |
|----------|--------|-----------|----------|--------|
| TRR9001  | T1040  | Network Sniffing | Linux | [`trr9001/lin`](trr9001/lin/README.md) |
| TRR9002  | T1609  | Command Execution in a Running Container | Kubernetes | [`trr9002/k8s`](trr9002/k8s/README.md) |
| TRR9003  | T1543.005 | Static Pod Persistence | Kubernetes | [`trr9003/k8s`](trr9003/k8s/README.md) |

## How to start a new TRR

1. Copy `templates/TRR-TEMPLATE.md` to `trrNNNN/<platform>/README.md`.
2. Make `trrNNNN/<platform>/ddms/` and `trrNNNN/<platform>/images/`.
3. Fill the template. Build one DDM per procedure: write the Arrows JSON in
   `ddms/`, then render its PNG with `python3 research/tools/render_ddm.py`.
4. Find the chokepoint. Write the Detection Strategy section.
5. Add a row to `index.json` and to the table above.
6. Build the atomics and Sigma rules the TRR calls for. Link them back by
   procedure ID.
