# Contributing to WOTS

WOTS collects our working builds of two projects that run Xbox Series X|S games natively on PC:

- **`xcl` branch:** XCL, an Xbox Series X|S → Windows compatibility layer. Retail games already run.
- **`leonida-boot` branch:** Leonida, the native PC recompilation of the Xbox version of GTA VI, with our
  newest boot work. The tooling is far along, but the game does not boot yet. **`leonida`** has the same
  project with only the merged pull requests.

Both need the same kinds of help. Below is what developers from our Discord (https://discord.gg/j3rmDxw5G) can pick up, and which
channel to talk about it in.

## Where you can help

### 1. Testing on your GPU (no coding needed) · `#compatibility`, `#bugs`
This is the most useful thing anyone can do. Both projects are mostly developed on AMD, and results
from other hardware are scarce.
- **NVIDIA and Intel** (32-wide subgroups): console wave64 shaders run emulated there. Run the GPU test
  suites and report any differences.
- Run the test suites on your machine and post the counts (passed / failed / skipped), your GPU and
  your driver.
- **XCL:** run the games you own and report what happens. Use `/bug` on the server and attach
  `report.json` and `xcl.log`.
- **Leonida:** check that your copy is detected, run the shader-translation and pipeline checks, and run the
  runtime tests on Windows, Linux (Wine/Proton) or macOS.

### 2. GPU and shader translation · `#gpu-shaders`
- **Leonida:**
  - wave64 cross-half operations in vertex, pixel and geometry shaders on 32-wide GPUs;
  - the vertex-shader input layout when the console runs VS as NGG;
  - mesh-shader draws.
- **XCL:**
  - whole-wave reductions in partial waves;
  - `image_sample_o` with an offset from a VGPR;
  - smaller HLSL output;
  - mesh pipelines that a newer retail game still has refused.

### 3. Graphics API: D3D12 / Vulkan · `#graphics-api`
- **Leonida (Xbox D3D12 → Vulkan):**
  - the console command-list tail and the descriptor-table record model;
  - indirect draw state and stream output;
  - the rest of the method surface tracked upstream.
- **XCL:**
  - binding console textures to the title's API (re-upload after writes);
  - the pipe/packer configuration for the `_X` modes;
  - MSAA;
  - draw-time binding of root arguments.
- **Ray tracing in both:**
  - BVH serialization;
  - whether a game rehydrates its prebuilt BVH packs or rebuilds them.

### 4. Kernel, runtime and loader · `#kernel-runtime`
- **XCL:** the XGameRuntime APIs that are still missing, such as XGameUI and XNetworking, and mapping
  physical pages at the game's address.
- **Leonida:** the PE loader and import shims, which work on a stand-in executable but have not been
  tested against the real one.

### 5. Input and audio · `#input-audio`
- **XCL:**
  - GameInput forwarded to the system GameInput.dll;
  - how a title feeds its Opus voices;
  - XMA2, which is low priority.
- **Leonida:**
  - the GameInput shim on SDL3 with more controllers;
  - per-track start offsets in the music and radio data.

### 6. Tools, docs and cross-platform
- Linux (Wine/Proton) and macOS (CrossOver, MoltenVK) runs and fixes.
- Keep the docs honest: if a doc says something works and it doesn't on your machine, report it or fix
  the doc.

## How to work with us

1. **Say what you're picking up** in `#working-on` before you start, so two people don't do the same thing.
2. **To write in the dev channels and speak in Dev Voice**, press **Apply for Developer** in `#roles`.
   A maintainer reviews every application.
3. **Fixes to XCL or Leonida go upstream.** Open the pull request against the original project and
   follow its own `CONTRIBUTING.md`, which is in each branch. Both projects require tests and small
   pull requests that do one thing each. The `xcl` and `leonida` branches here are our integration
   builds, made from what has been merged or proposed upstream.
4. **Keep each pull request to one change**, and say how you tested it: which GPU, which driver, what
   the tests reported.

## Hard rules

- **No game files, ever.** That means executables, archives, extracted assets, generated shaders,
  dumps, keys and `MicrosoftGame.config`. Don't put them in commits, issues, pull requests or on
  Discord. Everyone works on a copy they legally own.
- **No piracy, and no help with it.**
- **Licenses stay as they are:** XCL is GPL-2.0 and Leonida is GPL-3.0. Keep the copyright notices and
  the license files.
