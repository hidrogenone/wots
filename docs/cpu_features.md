# CPU instructions the executable needs

The Xbox Series CPU is an AMD Zen 2, and the runtime runs the game's code natively
([design.md](design.md), "Why a loader before a recompiler"). Code built for one known CPU can use every instruction
that CPU has without asking CPUID first. An instruction the host lacks raises `#UD`
(`STATUS_ILLEGAL_INSTRUCTION`) where it is reached, and a privileged one faults in user mode. This page records
which such instructions `game_scarlett_master.exe` contains, measured with `tools/cpu_feature_scan.py`. Counts only;
nothing from the executable is quoted.

## Reproduce

```powershell
python -I tools\cpu_feature_scan.py <game>\game_scarlett_master.exe            # summary
python -I tools\cpu_feature_scan.py <game>\game_scarlett_master.exe --sites    # plus the RVA of each flagged site
```

It streams MSVC `dumpbin /disasm:nobytes` (a few minutes for this executable, with no listing written to disk; a saved
listing works too, with `--image <exe>` for `.pdata`). Each instruction is mapped to the CPUID feature or privilege class it
needs, and each count is split by whether the site lies inside a `.pdata` function range. A linear disassembly also
decodes data in `.text` (jump tables, padding), so a hit outside every `.pdata` range is often not code; a leaf
function that does not touch the stack has no `.pdata` entry either, so those sites need a look by hand.

## Measured result (1.0.2.1)

26,674,075 instructions decoded in `.text`, 22,435,554 of them inside the 299,257 `.pdata` ranges.

| Feature | Class | Sites | Inside `.pdata` | What a host without it does |
|---|---|---:|---:|---|
| SSE4a (`insertq`) | AMD only | 19 | 17 | `#UD` on every Intel CPU |
| CLZERO | AMD only | 10 | 0 | `#UD` on every Intel CPU |
| MONITORX (`monitorx`, `mwaitx`) | AMD only | 4 | 4 | `#UD` on every Intel CPU |
| CLWB | newer Intel only | 8 | 6 | `#UD` on Intel client CPUs before Ice Lake / Tiger Lake (Skylake to Comet Lake) |
| Port I/O, `cli`/`hlt` | privileged | 8 | 2 | fault in user mode |
| `int n` (not 3/29h/2Ch/2Dh) | kernel call | 1 | 1 | a software interrupt Windows does not serve |
| CPUID / XGETBV | host query | 9 / 2 | 9 / 2 | run everywhere; answer with the host's values |

Each flagged site was read by hand in a private copy (not quoted here):

- All 41 SSE4a, CLZERO, MONITORX and CLWB sites are real code: each sits among instructions of the same kind of
  code (vector arithmetic around the `insertq` sites, cache-line loops around CLZERO and CLWB, a wait on a memory
  address around the two `monitorx`/`mwaitx` pairs). The 10 CLZERO sites are one leaf routine, a cache-line zeroing
  loop with no `.pdata` entry, which is why none of them is inside a `.pdata` range.
- The 8 privileged and 1 `int n` hits are data: tables of 32-bit offsets placed in `.text` (some inside a `.pdata`
  range) that the linear sweep decodes as instructions. They are listed for completeness, not as code to replace.

No AVX-512, VAES, VPCLMULQDQ, SHA, RDPID, RDPRU, XOP, FMA4, TBM, SYSCALL or SYSENTER instruction was found. The
256-bit integer, FMA3, F16C, BMI1/2, ADX, MOVBE, AES-NI and PCLMULQDQ instructions it uses are on every Intel CPU
since Haswell/Broadwell and every AMD CPU since Zen, so they are counted but not flagged. No RDTSC or RDTSCP is
in the image.

## What it means for the runtime

- On an AMD Zen 2 or later host every flagged user-mode instruction runs as on the console.
- On an Intel host the SSE4a, CLZERO and MONITORX sites, and on Intel client CPUs before Ice Lake the CLWB sites,
  raise `STATUS_ILLEGAL_INSTRUCTION` when reached. `gta6rt` emulates them (`runtime/src/cpu_emulation.h`, see
  [runtime/README.md](../runtime/README.md), "PE loader"): CLZERO zeroes the 64-byte line, CLWB is a write-back hint
  with nothing to do on coherent memory, MWAITX returns at once (an early return is one the manual allows), and
  `insertq`/`extrq` are bit-field operations on the low quadword. `cpu_emulation_test` checks each form against the
  CPU on a host that has it and against the handler on one that does not (an i7-10700K: all four lacking, all checks
  pass).
- The CPUID sites see the host's vendor, family and features, not the console's. What the game does with the
  answers is not measured here.

## The zeroing loop

The 10 CLZERO sites are one routine that zeroes memory a cache line at a time, each with the same four instructions:

```
clzero                ; zero the line rax points into
add  rax, 64
cmp  rax, <register>  ; the end of the range
jb   <the clzero>
```

Emulated one instruction at a time, that is one `#UD` round trip for every 64 bytes. `cpu_emulation_test` times the
loop over 1 MiB (16,376 lines) on an i9-14900KF, which has no CLZERO: **31.8 ms**, about 1.9 us a line.

A boot reaches this loop, and its frame loop runs it all the time. Measured on a retail boot (own 1.0.2.1 copy,
i9-14900KF, RTX 5070, Windows 11, `LEONIDA_D3D12=vulkan`, `main` with the open boot-chain pull requests merged
locally up to a steady frame loop that presents): one title thread was at 100 % of a core and 4 of 24 stack samples
found it on the CLZERO itself; the title presented about **2.4 frames a second** (167 frames in 68 s).

So the handler finishes the loop in the trap of its first CLZERO (`finish_clzero_loop` in
`runtime/src/cpu_emulation.h`). When the bytes after an emulated CLZERO are exactly that tail, it zeroes every further
line the loop would, leaves RAX, the arithmetic flags and RIP as the loop does, and continues after the branch. A line
that cannot be written ends it early, with RIP back at the CLZERO and RAX in that line, so that iteration traps again
and raises its access violation as the instruction does. Any other code after a CLZERO is emulated as before.

| | Before | After |
|---|---:|---:|
| 1 MiB loop in `cpu_emulation_test` | 31.8 ms | 0.02 to 0.04 ms |
| Retail frame loop, frames presented a second | about 2.4 | about 46 (6,000 in 129 s) |

The first loop the boot ran through it zeroed 229 lines in one trap. This does not change what the title draws: the
frames were black before and after.

Not measured: which of these sites a boot reaches, and in which order.
