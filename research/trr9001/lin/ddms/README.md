# Detection Data Models — TRR9001.LIN

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9001/lin/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or
older than its JSON.

Colours: green = the sniffing process (user space), blue = the kernel, black =
an abstract step. Shaded = the primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9001_lin_a` | TRR9001.LIN.A — raw packet socket | `socket(AF_PACKET)` (chokepoint, shared with B) |
| `trr9001_lin_b` | TRR9001.LIN.B — `PACKET_MMAP` ring | `socket(AF_PACKET)` (chokepoint, shared with A) |
| `trr9001_lin_c` | TRR9001.LIN.C — raw IP socket | `socket(AF_INET/AF_INET6, SOCK_RAW)` |
| `trr9001_lin_d` | TRR9001.LIN.D — eBPF / XDP capture | `bpf(BPF_PROG_LOAD)` and `socket(AF_XDP)` |
