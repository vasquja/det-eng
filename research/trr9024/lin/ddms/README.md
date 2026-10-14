# Detection Data Models — TRR9024.LIN

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9024/lin/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or
older than its JSON.

Colours: green = the installing process (user space), blue = the kernel, black =
an abstract step. Shaded = the primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9024_lin_a` | TRR9024.LIN.A — eBPF program load | `bpf(BPF_PROG_LOAD)` (`a0=0x5`) — built + proven |
| `trr9024_lin_b` | TRR9024.LIN.B — loadable kernel module | `finit_module` / `init_module` — gap |
| `trr9024_lin_c` | TRR9024.LIN.C — userland preload | write to `/etc/ld.so.preload` — gap |
