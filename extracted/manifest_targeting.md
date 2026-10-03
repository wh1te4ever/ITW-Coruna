# manifest.csv / manifest.json — iOS targeting columns

Both files carry 11 extra columns after the original 12, and they mirror each other. The original
columns are unchanged (byte-for-byte for the CSV, key-for-key for the JSON); the pre-annotation
files are kept as `manifest.csv.orig` / `manifest.json.orig`.
Regenerate with `python3 annotate_targeting.py --write`.

| column | meaning |
|---|---|
| `target_id` | the u32 at `entry+0x00` of the selection config that selects this file |
| `id_class` | bits [31:24] — payload family + target-process ABI |
| `id_bucket` | bits [23:20] — the iOS version bucket (`-` for the A-family, which has none) |
| `id_subvar` | bits [19:16] — sub-variant (F-family) / the whole selector byte (A-family) |
| `target_proc_abi` | arm64 / arm64e — **the ABI of the process being injected into, not the device.** See below |
| `ios_min`, `ios_max` | outer envelope of the version window; `*` means *no bound exists in the code* |
| `ios_target` | human-readable window, including secondary windows |
| `select_gate` | the exact condition in the loader, with the hex constants |
| `role` | what the artifact is |
| `confidence` | high = read directly out of the loader; medium = inferred as described below |

## Where every value comes from

All of it is read out of **`macho/443786dae18e7c0a_arm64_DYLIB.macho`** (= `payloads/bootstrap.dylib`
in the upstream repo, 89 328 bytes). It is the **only** artifact in this capture that contains the
config magic `0x12345678`, the ID class bytes and the version-bucket constants. All four other
Mach-Os were checked function by function: `dbed4a5b` (arm64) and `0a8a6258` (arm64e) are the two
byte-identical slices of the `322f8877` FAT and are **not** selectors — they share only the
`SystemVersion.plist` reader and a verbatim copy of the bucket-`0x90` predicate, and `dbed4a5b`'s
large version tree (`sub_5208`, exact releases 13.0–16.7) is an ObjC/dyld patch-site table, i.e.
"which releases can be patched", not payload selection. `native/1f25a4f5…` is the carved `__TEXT`
of a loader that embeds that FAT at offset `0x1D0`, so its five `SystemVersion.plist` hits are one
loader plus 2×2 embedded-slice strings — not five competing tables.

Consequence: one table covers every family, and **no row's range is corroborated by a second
build**.

```
0x7090  sub_7090   reads /System/Cryptexes/OS/System/Library/CoreServices/SystemVersion.plist
                   (fallback /System/Library/CoreServices/SystemVersion.plist), key "ProductVersion",
                   sscanf "%d.%d.%d", packs  ver = (major<<16) | (minor<<8) | patch
0x7828             stores ver to ctx+0xC0            (so 16.5.1 -> 0x100501, 15.7.7 -> 0x0F0707)
0x77F0             stores hw.cpufamily (commpage, via _get_cpu_capabilities) to ctx+0xE0
0xAB8C  sub_AB8C   ver -> bucket byte in bits [23:16]
0x9B60  sub_9B60   the "newest bucket" predicate (also consults cpufamily and hw.model)
0xA294  sub_A294   composes the 0xF2/0xF3 IDs  (class byte at 0xA3AC/0xA3B0, sub-variant at 0xA320/0xA378)
0xA418  sub_A418   composes the 0xA2/0xA3 IDs  (class byte at 0xA7DC/0xA7E0, pairs at 0xA7A8/0xA7AC and 0xA7C8/0xA7CC)
0x9CB8  sub_9CB8   composes the second-level 0x02/0xE2 (and 0x10..0x13) IDs
0x9F18  sub_9F18   the lookup: validates magic 0x12345678, count at cfg+0x108, entries at cfg+0x10C,
                   stride 0x64, exact u32 compare on entry+0x00, returns entry+0x04 as the 32-byte
                   ChaCha20 key, name at entry+0x24 (64 bytes)
```

### Bucket function, transcribed

```c
// sub_AB8C @0xAB8C
if (sub_9B60(ctx) & 1) return 0x900000;
v = *(u32*)(ctx + 0xC0);
if (v <= 0x100500) {                         // <= 16.5.0
    if (v >> 20) return 0x700000;            // 16.0.0 - 16.5.0
    v3 = (v <= 0x0DFFFF) ? 0x300000          // <= 13.x
                         : 0x400000;         // 14.0+
    if (v >  0x0E04FF) v3 = 0x700000;        // > 14.4.255
    if (v <= 0x0F0706) return v3;            // <= 15.7.6
    return 0x800000;
}
return 0x800000;                             // > 16.5.0
```

```c
// sub_9B60 @0x9B60  -> 1 means "use bucket 0x90"
if (v > 0x1006FF) return 1;                              // 16.7.0 and up, incl. 17.x
if (v <= 0x100400) {
    if ((u32)(v - 0x0F0707) < 0x0F8F9) return 1;         // 15.7.7 .. 15.255.255
    if ((u32)(v - 0x0F0200) >> 9 <= 0x7E)                // 15.2.0 .. 15.255.255
        if (sysctlbyname("hw.model", ...) == 0 && (model[0] & 0xDF) == 0x4A /* 'J' = iPad */)
            return (*(u64*)(ctx + 0x640) - 0x40000001) >> 30 == 0;
} else {                                                  // 16.4.1 .. 16.6.255
    return !(cpufamily in {0x8765EDEA, 0xDA33D83D, 0x1B588BB3, 0x462504D2});
}
return 0;
```

The four cpufamily constants are the A16, A15, A14 and A13 `CPUFAMILY_*` values. So on anything
older than an A13, iOS 16.4.1–16.6.x falls through to bucket `0x90` instead of `0x70`/`0x80`.

### Sub-variants — and why they are *not* a version axis

`sub_A294` adds one nibble into bits [19:16], gated by the byte at `ctx+0x5E8`:

```
+3 (0x30000)  (ver - 0x100400) >> 10 <= 0x3E  AND cpufamily in {A13, A14, A15, A16}   (0xA300-0xA368)
+5 (0x50000)  (ver - 0x100000) < 0x401, i.e. 16.0.0 - 16.4.0                          (0xA370-0xA37C)
 0            otherwise, or when the ctx+0x5E8 gate is clear
```

`ctx+0x5E8` is **not** a version test — it is a sandbox probe, set by `sub_89CC` @`0x89CC`
(`sandbox_check(getpid(), "iokit-open-service", NO_REPORT, "IOSurfaceRoot")` for
`0x100000 <= ver <= 0x100500`, a second probe above that, stored at `0x8AE8`) and read at `0xA2E4`.
So the *same* iOS version can select `0xF270` or `0xF275`, and `0xF280` or `0xF283`, depending on
runtime sandbox reachability. Treat base and sub-variant rows as alternates for one version window,
not as two different windows.

iOS 16.4.0 exactly falls in both windows; the `+3` branch is tested first, so **16.4.0 on A13–A16
yields `+3`, and on any older SoC `+5`**.

`sub_A418` (A-family) uses the whole `[23:16]` byte as the selector and picks between a pair with
the byte at `ctx+0x5E9`:

```
+3 / +4   ver >= 0x100400 AND cpufamily in {A13..A16}     (+3 if ctx+0x5E9 == 0, else +4)
+5 / +6   (ver - 0x100000) <= 0x400, i.e. 16.0.0 - 16.4.0 (+5 if ctx+0x5E9 == 0, else +6)
 0        sub_9B60 returned 1 -> ID becomes 0 and no A-family payload is used
```

### Architecture half — a separate axis, and it describes the *process*

```asm
0xA3A4  LDR  W8, [X24,#0xDC]
0xA3A8  CMP  W8, #1
0xA3AC  MOV  W8, #0xF2000000        ; arm64
0xA3B0  MOV  W9, #0xF3000000        ; arm64e
0xA3B4  CSEL W8, W9, W8, HI
0xA3B8  ORR  W9, W0, W25            ; bucket | sub-variant
0xA3BC  ORR  W1, W9, W8             ; | class byte   <- the whole ID, one expression
```
Same shape at `0xA7D4`–`0xA7E4` for `0xA2`/`0xA3` and at `0x9DCC`/`0x9E2C` for `0x02`/`0xE2`, and
`sub_9CB8` calls the *same* `sub_AB8C` (`0x9D18`, `0x9E00`). Neither `sub_AB8C` nor `sub_9B60` ever
touches `ctx+0xDB`/`ctx+0xDC` — the only reads of those offsets in the whole binary are inside the
class-byte selection (`0x9D28`, `0x9E08`, `0x9E20`, `0xA38C`, `0xA3A4`, `0xA7D4`). So `0xF3xx` /
`0xA3xx` / `0xE2xx` use **exactly** the same version thresholds as `0xF2xx` / `0xA2xx` / `0x02xx`:
the ABI is an independent OR term, never a version qualifier.

**`ctx+0xDC` is the cpusubtype of the targeted process's main image** (`task_info`/
`TASK_DYLD_INFO`), so `target_proc_abi` names the victim-process ABI — not the device and not the OS
build. The same device on the same iOS can land in either family depending on what is injected. The
only secondary implication is that an arm64e target implies A12-or-newer hardware.

Independently confirmed from the data: for all 19 top-level bundles, every Mach-O inside a
`0x_2__` bundle has cpusubtype `CPU_SUBTYPE_ARM64_ALL` and every Mach-O inside a `0x_3__`
bundle has `CPU_SUBTYPE_ARM64E` — 19/19, no exceptions. With all 30 blobs now decrypted this also
holds for **all 10** second-level modules (`0x02…` = arm64, `0xE2…` = arm64e), 10/10.

## Resulting table

| `[23:16]` | iOS window | extra gate |
|---|---|---|
| `0x30` | 13.x **and everything older** (the only constraint is `ver <= 0x0DFFFF`) | — |
| `0x40` | 14.0 – 14.4.x | — |
| `0x70` | 14.5 – 15.7.6; also 16.0 – 16.5.0 when the sandbox gate is clear | — |
| `0x73` | 16.4 – 16.5 | A13–A16 only, sandbox gate set |
| `0x75` | 16.0 – 16.4.0 (16.4.0 itself only on pre-A13) | sandbox gate set |
| `0x80` | 16.5.1 – 16.6.x | A13–A16 only (older SoCs divert to `0x90`), sandbox gate clear |
| `0x83` | 16.5.1 – 16.6.x | A13–A16 only, sandbox gate set |
| `0x90` | four disjoint conditions, see below | — |
| `0x03`/`0x04` (A-family) | 16.4 – 16.6.x | A13–A16, `ctx+0x5E9` picks which |
| `0x05`/`0x06` (A-family) | 16.0 – 16.4.0 | `ctx+0x5E9` picks which |

Bucket `0x90` is not one range — `sub_9B60` returns 1 on **any** of:

1. `ver > 0x1006FF` → iOS 16.7 and up. Unbounded in `sub_AB8C`, but `_process` caps it:
   ```asm
   0x6A44  LDR  w8, [x19,#0xC0]      ; ver
   0x6A48  MOVZ w9, #0x2FF
   0x6A4C  MOVK w9, #0x11, lsl#16    ; w9 = 0x1102FF  = 17.2.255
   0x6A54  CMP  w8, w9
   0x6A58  B.HI -> 0x69BC            ; 0x69BC is the epilogue -> bail
   ```
   So **17.2.255 is a real code cap**, not campaign dating.
2. `0x0F0707 <= ver <= 0x0FFFFF` → 15.7.7 – 15.x;
3. iOS 16.4.1 – 16.6.x on a SoC **outside** the A13–A16 set. This is the clause that catches an
   A12 (`cpufamily 0x07D34B9F`) on 16.5.0;
4. iPad-class devices (`hw.model[0] & 0xDF == 0x4A`, i.e. `'J'`) on **15.2.0 – 15.7.6** with
   `(*(u64*)(ctx+0x640) - 0x40000001) >> 30 == 0`, i.e. **memory size in (1 GiB, 2 GiB]**.

A single `ios_min`/`ios_max` pair cannot express that, so the condition text lives in `select_gate`.

The A-family (`0xA2`/`0xA3`) has **no bucket byte at all** — the version lives only in the nibble
3/4/5/6, and the family exists only for iOS 16.0 – 16.6.x: if `sub_9B60` is true, `sub_A418` emits
no ID at all (hence there are no `0xA2 9x`/`0xA3 9x` rows), and the whole path additionally needs
the `ctx+0x5E8` gate (`0xA4A0`).

Worked through for the three devices in the upstream README's "Tested on" table. `sub_9B60` runs
*before* the bucket arithmetic, which is what decides two of these:

| device | iOS | `ver` | path | computed ID |
|---|---|---|---|---|
| iPhone 6s+ (A9) | 15.4.1 | `0x0F0401` | `sub_9B60`: clause (d) window matches but `hw.model` is `N…`, not `J…` → 0. `sub_AB8C`: `> 0x0E04FF`, `<= 0x0F0706` → bucket `0x70` | `0xF2700000` |
| iPhone Xs Max (A12) | 16.5.0 | `0x100500` | `0x100400 < ver <= 0x1006FF` and cpufamily `0x07D34B9F` is **not** A13–A16 → `sub_9B60` = 1 → bucket `0x90` | `0xF3900000` |
| iPhone 15 Pro Max (A17 Pro) | 17.0 | `0x110000` | `> 0x1006FF` → `sub_9B60` = 1 → bucket `0x90` | `0xF3900000` |

(The Xs Max row is the easy one to get wrong: `0x100500 <= 0x100500` tempts you into bucket `0x70`,
but `sub_9B60`'s cpufamily clause fires first and sends any pre-A13 SoC on 16.4.1–16.6.x to `0x90`.)

## Second-level modules (the 10 `0x02…` / `0xE2…` rows)

Their ChaCha20 keys are **not** in the `7a7d99` manifest. Each parent bundle carries a nested
`0x12345678` config as its last `type 0x07` entry (468 B = `0x10c` header + 2 × `0x64`), holding the
id, 32-byte key and name of the two modules it chains to. Harvesting those
(`child_keys_from_decrypted()` in `extract.py`) takes the extraction from 24/30 to **30/30 blobs,
66 Mach-O**, still fully static — no device, no runtime key dump.

Decrypted, the 10 modules de-duplicate to **3 distinct binaries**, all with install name
`/usr/local/lib/SamplePayload.dylib` and referencing `powerd.bundle/powerd` and `/tmp/upgrade.dylib`:

| sha256 | size | arch | served as |
|---|---|---|---|
| `e258c0b70ed7b4be…` | 715 760 | arm64 | `0x02300000`, `0x02400000`, `0x02700000`, `0x02800000` |
| `63ffff883f78ecca…` | 715 760 | arm64 | `0x02900000` only |
| `59592bc95876eaf3…` | 747 936 | arm64e (PAC) | all five `0xe2…` IDs |

So at the second level the version bucketing is largely cosmetic — the same binary is re-keyed and
re-named per bucket — with one real exception: the `0x90` bucket gets its own arm64 build.

## Caveats

- **`ANALYSIS.md` upstream disagrees and is wrong here.** Its table (`0xf230` = iOS 15.x,
  `0xf240` = 16.0–16.2, `0xf280` = 16.3–16.5, `0xf270` = 16.6–17.0) does not match the loader's own
  thresholds, and would route a 15.4.1 device to `0xf230` where the code computes `0xf270`. The
  upstream README itself says that file was generated rather than derived.
- The windows are what **this** bootstrap build computes, and it is the only build in the capture
  that computes any; nothing here is cross-checked against a second selector.
  `0xF280`/`0xF380` in particular are only reachable while the `ctx+0x5E8` sub-variant gate is clear.
- **`*` in `ios_min`/`ios_max` means "no bound in the code", not "unknown".** Only bucket `0x30`
  carries one: `sub_AB8C`'s single constraint is `ver <= 0x0DFFFF`, so it covers 12.x and older as
  well as 13.x, and it is also where a *failed* version parse lands (`ctx+0xC0` left 0). A separate
  64-bit guard on `ctx+0xD0` at `0x6928`–`0x6958` can still bail out, so how far back the chain is
  actually usable is not established here. The upper end is not open: `_process` rejects
  `ver > 0x1102FF` (17.2.255) at `0x6A44`–`0x6A58`.
- `target_proc_abi` is the **injected process's** ABI (`task_info`/`TASK_DYLD_INFO` cpusubtype), not
  the device's. Do not read `arm64` as "this victim had a pre-A12 phone".
- Rows marked `confidence=medium` are the second-level IDs `0x0230/0xE230/0x0240/0xE240`: their
  bucket byte is inherited from the parent bundle, but `sub_9CB8` in this build would emit class
  `0x10`/`0x11` rather than `0x02`/`0xE2` for those versions, so they are not reproducible from this
  binary alone.
- The `ctx+0x5E8` / `ctx+0x5E9` / `ctx+0xDB` flags are never written inside this dylib — they are
  supplied by the caller, so which member of a sub-variant pair is used cannot be determined
  statically from this artifact.
- Rows with no `target_id` are not ID-selected at all (the manifest itself, the bootstrap variants,
  the carved `__text` blob, the next-stage JS).
