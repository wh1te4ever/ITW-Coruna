#!/usr/bin/env python3
"""Append iOS-targeting columns to extracted/manifest.csv.

Every added value is derived from the payload-selection logic in the Stage-3
bootstrap  extracted/macho/443786dae18e7c0a_arm64_DYLIB.macho  (= payloads/bootstrap.dylib),
which is the only artifact in this capture that contains the config magic 0x12345678,
the ID class bytes and the version-bucket constants.

  ver            = (major<<16)|(minor<<8)|patch, parsed from SystemVersion.plist
                   "ProductVersion" by sub_7090 @0x7090, stored to ctx+0xC0 @0x7828
  bucket [23:16] = sub_AB8C @0xAB8C, with the "newest" predicate sub_9B60 @0x9B60
  sub-variant    = sub_A294 @0xA294 (F-family) / sub_A418 @0xA418 (A-family)
  class  [31:24] = arm64 vs arm64e from *(u32*)(ctx+0xDC)
  lookup         = sub_9F18 @0x9F18 (exact u32 compare on entry+0x00)
"""
import csv, json, os, struct, importlib.util, glob, hashlib, shutil, sys

ROOT = '/Users/seo/Downloads/ITW-Coruna-main/ITW-Coruna-main'
EXT  = os.path.join(ROOT, 'extracted')
CSV  = os.path.join(EXT, 'manifest.csv')

_spec = importlib.util.spec_from_file_location('ex', os.path.join(ROOT, 'extract.py'))
ex = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(ex)
BED, FOOD, CFG = 0x0BEDF00D, 0xF00DBEEF, 0x12345678
NUL = b'\x00'

# --------------------------------------------------------------- mapping table
# Bits [23:16] of the target ID, already intersected (bucket window AND sub-variant window).
# Only these 12 values occur in the capture.  cpufam = {A13 0x462504D2, A14 0x1B588BB3,
# A15 0xDA33D83D, A16 0x8765EDEA}.
A13_16 = 'cpufamily in {A13 0x462504D2, A14 0x1B588BB3, A15 0xDA33D83D, A16 0x8765EDEA}'
# The sub-variant gate is not a version test: it is a sandbox probe on the injected process
# itself, so the SAME iOS version can yield 0xF270 or 0xF275 (and 0xF280 or 0xF283) depending on
# where the code runs. gate = (sandbox_check(...) > 0), i.e. 1 means DENIED / confined.
GATE = ('the ctx+0x5E8 sandbox gate must be SET (sub_89CC @0x89CC, stored 0x8AE8, read 0xA2E4/0xA4A0: '
        'gate = sandbox_check(getpid(), ...) > 0, so 1 = the injected process is denied/confined. '
        '0x100000 <= ver <= 0x100500 probes sandbox_check(getpid(),"iokit-open-service",'
        'SANDBOX_CHECK_NO_REPORT,"IOSurfaceRoot"); ver > 0x100500 probes sandbox_check(getpid(),NULL,0) '
        '= "sandboxed at all"; otherwise the probe is skipped and the gate is always 0)')
# ctx+0x5E9 is a recent-silicon flag, NOT a sandbox or runtime-unknown flag.
E9 = ('ctx+0x5E9 (set at 0x7A48-0x7A90: ver >= 0x0F0400 AND cpufamily in '
      '{A15 0xDA33D83D, A16 0x8765EDEA, A17 Pro 0x2876F5B5})')
# '*' in ios_min / ios_max means "no bound in the code", not "unknown".
HI_F = {   # F-family (0xF2/0xF3) and second-level (0x02/0xE2): bucket | sub-variant
 0x30: ('*', '13.7',   'iOS 13.x and below - no lower bound in sub_AB8C, so 12.x and older too; '
                      'also the fallback when the version parse fails (ctx+0xC0 left 0)',
        'sub_AB8C: ver <= 0x0DFFFF (0xABE8 mov w11,#0xDFFFF / 0xABF8 mov w11,#0x300000). A separate '
        '64-bit guard on ctx+0xD0 at 0x6928-0x6958 can still bail out, so how far back this is '
        'actually usable is not established here'),
 0x40: ('14.0', '14.4',   'iOS 14.0 - 14.4.x',
        'sub_AB8C: 0x0E0000 <= ver <= 0x0E04FF (0xABEC add w12,w11,#0x500 / 0xABFC mov w14,#0x400000)'),
 0x70: ('14.5', '15.7.6', 'iOS 14.5 - 15.7.6; also 16.0 - 16.4.0 on any SoC and 16.4.1 - 16.5.0 on '
                          'A13-A16, when the sandbox gate is clear',
        'sub_AB8C: 0x0E0500 <= ver <= 0x0F0706, or 0x100000 <= ver <= 0x100500 while the '
        + GATE.replace('must be set', 'is clear')
        + '. Carve-outs from sub_9B60, which runs FIRST: 15.2.0-15.7.6 on an iPad-class device '
          'diverts to 0x90, and 16.4.1-16.5.0 stays here only if ' + A13_16),
 0x73: ('16.4', '16.5',   'iOS 16.4 - 16.5 on A13-A16',
        'bucket 0x70 (ver <= 0x100500) AND sub_A294 +3 (0xA300-0xA368): (ver - 0x100400) >> 10 <= 0x3E '
        'AND ' + A13_16 + '; ' + GATE),
 0x75: ('16.0', '16.4',   'iOS 16.0 - 16.4.0 (16.4.0 itself only on pre-A13; A13-A16 take +3)',
        'bucket 0x70 AND sub_A294 +5 (0xA370-0xA37C): (ver - 0x100000) < 0x401; ' + GATE),
 0x80: ('16.5.1', '16.6.x', 'iOS 16.5.1 - 16.6.x on A13-A16, when the sandbox gate is clear',
        'sub_AB8C: ver > 0x100500, reachable only while sub_9B60 returns 0, which above '
        '0x100500 requires ' + A13_16 + ' (other SoCs divert to bucket 0x90)'),
 0x83: ('16.5.1', '16.6.x', 'iOS 16.5.1 - 16.6.x on A13-A16',
        'bucket 0x80 (ver > 0x100500) AND sub_A294 +3: ' + A13_16 + '; ' + GATE),
 0x90: ('15.2', '17.2.255', 'iOS 16.7 - 17.2.255; also 15.7.7 - 15.x; 16.4.1 - 16.6.x on SoCs outside '
        'A13-A16; and iPad-class devices with 1-2 GiB RAM on 15.2 - 15.7.6',
        'sub_9B60 returns 1 on any of: (a) ver > 0x1006FF - unbounded in sub_AB8C itself, but '
        '_process bails at 0x6A44-0x6A58 (cmp against 0x1102FF, b.hi -> epilogue 0x69BC), so the '
        'real cap is 17.2.255; (b) 0x0F0707 <= ver <= 0x0FFFFF; (c) 0x100400 < ver <= 0x1006FF with '
        'cpufamily NOT in the A13-A16 set - this is why an A12 on 16.5.0 lands here, not in 0x70/0x80; '
        '(d) 0x0F0200 <= ver <= 0x0F0706 with hw.model[0] & 0xDF == 0x4A ("J" = iPad-class) and '
        '(*(u64*)(ctx+0x640) - 0x40000001) >> 30 == 0, i.e. memory size in (1 GiB, 2 GiB]'),
}

HI_A = {   # A-family (0xA2/0xA3): no bucket byte at all - bits [19:16] alone carry the version,
           # and the family only exists for iOS 16.0 - 16.6.x (sub_9B60 true => no ID is emitted).
 0x03: ('16.4', '16.6.x', 'iOS 16.4 - 16.6.x on A13/A14 (pre-A15 of the gated set)',
        'sub_A418 (0xA500-0xA524, 0xA780-0xA7F4): ver >= 0x100400 AND ' + A13_16
        + '; pair member chosen by ' + E9 + ' == 0; whole path also needs ' + GATE),
 0x04: ('16.4', '16.6.x', 'iOS 16.4 - 16.6.x on A15/A16/A17 Pro',
        'as 0x03 but ' + E9 + ' != 0'),
 0x05: ('16.0', '16.4',   'iOS 16.0 - 16.4.0 on pre-A15 silicon, or below 15.4',
        'sub_A418: (ver - 0x100000) <= 0x400; pair member chosen by ' + E9 + ' == 0; also needs ' + GATE),
 0x06: ('16.0', '16.4',   'iOS 16.0 - 16.4.0 on A15/A16/A17 Pro',
        'as 0x05 but ' + E9 + ' != 0'),
}

# The class byte is NOT a device/OS property: ctx+0xDC is the cpusubtype of the *targeted
# process's* main image (task_info/TASK_DYLD_INFO), so it names the victim-process ABI.
# The same device on the same iOS can land in either family depending on what is injected.
# Only secondary implication: an arm64e target implies A12-or-newer hardware.
CLASS = {
    0xF2: ('arm64',  'stage3 payload bundle (F-family, selected by sub_A294 @0xA294)', '0xA3AC: ctx+0xDC <= 1'),
    0xF3: ('arm64e', 'stage3 payload bundle (F-family, selected by sub_A294 @0xA294)', '0xA3B0: ctx+0xDC > 1'),
    0xA2: ('arm64',  'stage3 payload bundle (A-family, selected by sub_A418 @0xA418)', '0xA7DC: ctx+0xDC <= 1'),
    0xA3: ('arm64e', 'stage3 payload bundle (A-family, selected by sub_A418 @0xA418)', '0xA7E0: ctx+0xDC > 1'),
    0x02: ('arm64',  'second-level module (/usr/local/lib/SamplePayload.dylib), bucket inherited from the parent bundle (sub_9CB8 @0x9CB8)', '0x9DC8: ctx+0xDC <= 1'),
    0xE2: ('arm64e', 'second-level module (/usr/local/lib/SamplePayload.dylib), bucket inherited from the parent bundle (sub_9CB8 @0x9CB8)', '0x9DCC: ctx+0xDC > 1'),
}


def decode(tid):
    """full u32 target ID -> annotation dict"""
    cls = (tid >> 24) & 0xFF
    hi  = (tid >> 16) & 0xFF
    arch, role, arch_ev = CLASS[cls]
    if cls in (0xA2, 0xA3):
        lo, hi_v, rng, gate = HI_A[hi]
        bucket_s, sub_s = '-', f'0x{hi:02x}'
    else:
        lo, hi_v, rng, gate = HI_F[hi]
        bucket_s = f'0x{hi & 0xF0:02x}'
        sub_s = f'+{hi & 0x0F}' if (hi & 0x0F) else ''
    return dict(target_id=f'0x{tid:08x}', id_class=f'0x{cls:02x}', bucket=bucket_s,
                subvar=sub_s, target_proc_abi=arch,
                ios_min=lo, ios_max=hi_v, ios_target=rng,
                select_gate=gate, role=role, arch_evidence=arch_ev)


# --------------------------------------------------------------- read the data
def load_facts():
    raw = open(os.path.join(EXT, 'decrypted_raw/c46f10963abb667a_x_qbrdr_enc.bin'), 'rb').read()
    m = ex.try_lzma(raw[8:])
    n = struct.unpack_from('<I', m, 0x18 + 0x108)[0]
    top, p = {}, 0x18 + 0x10c
    for _ in range(n):
        e = m[p:p + 0x64]
        top[e[0x24:0x64].split(NUL)[0].decode().split('.')[0]] = struct.unpack_from('<I', e, 0)[0]
        p += 0x64
    # second-level IDs: the nested 0x12345678 config inside each decrypted bundle
    child = {}
    for f in glob.glob(os.path.join(EXT, 'decrypted_raw/*.bin')):
        d = open(f, 'rb').read()
        if struct.unpack_from('<I', d, 0)[0] == BED:
            d = ex.try_lzma(d[8:])
        if not d or struct.unpack_from('<I', d, 0)[0] != FOOD:
            continue
        cnt = struct.unpack_from('<I', d, 4)[0]; p = 8
        for _ in range(cnt):
            et, res, off, ln = struct.unpack_from('<IIII', d, p); p += 16
            blob = d[off:off + ln]
            dat = ex.try_lzma(blob[8:]) if struct.unpack_from('<I', blob, 0)[0] == BED else blob
            if dat is None or len(dat) < 0x10c or struct.unpack_from('<I', dat, 0)[0] != CFG:
                continue
            k = struct.unpack_from('<I', dat, 0x108)[0]; q = 0x10c
            for _ in range(k):
                e = dat[q:q + 0x64]
                child[e[0x24:0x64].split(NUL)[0].decode().split('.')[0]] = struct.unpack_from('<I', e, 0)[0]
                q += 0x64
    return top, child


# --------------------------------------------------------------- non-keyed rows
# these artifacts are not selected by a target ID; annotate what they actually are
STATIC = {
 'macho/443786dae18e7c0a_arm64_DYLIB.macho': dict(
    role='stage3 native bootstrap / payload selector (= payloads/bootstrap.dylib) - the ONLY selector in the capture',
    ios_target='all targets - this binary IS the selector',
    select_gate='the only artifact holding the 0x12345678 table, the ID class bytes and the bucket constants: '
                'sub_7090/0x7090 version parse, sub_AB8C/0xAB8C buckets, sub_9B60/0x9B60 predicate, '
                'sub_A294/sub_A418/sub_9CB8 ID composition, sub_9F18/0x9F18 lookup'),
 'macho/dbed4a5b75bfa373_arm64_DYLIB.macho': dict(
    role='loader component, arm64 slice of the embedded FAT (322f8877...) - NOT a selector',
    ios_target='no target ID',
    select_gate='no 0x12345678 table, no bucket byte, no class byte. Shares only the SystemVersion.plist '
                'reader (0x9A34) and the 0x90-bucket predicate (sub_A52C, constant-for-constant identical to '
                'sub_9B60). Its big version tree (sub_5208) is an ObjC/dyld patch-site table keyed on exact '
                'releases 13.0-16.7 - that is "which releases can be patched", not payload selection'),
 'macho/0a8a6258a8558d83_arm64e_DYLIB.macho': dict(
    role='loader component, arm64e slice of the embedded FAT; also shipped as entry #2 (type 0x0a) of the '
         '0xa3030000 / 0xa3040000 bundles - NOT a selector',
    ios_target='no target ID',
    select_gate='no 0x12345678 table, no bucket byte, no class byte; ctx+0xDC written once and never read. '
                'Shares the SystemVersion.plist reader (0x9B3C) and the predicate (sub_A67C, identical '
                'constants to sub_9B60) - a cross-arch corroboration of the 0x90 condition, nothing more'),
 'macho/322f8877729e126a_arm64+arm64e_FAT.macho': dict(
    role='FAT container = dbed4a5b75bfa373 (arm64, off 0x4000) + 0a8a6258a8558d83 (arm64e, off 0x1c000), slices byte-identical',
    ios_target='no target ID',
    select_gate='container only; its own blob parser uses magic 0xF00DBEEF with a 0x10 stride, not 0x12345678/0x64'),
 'native/1f25a4f580e22397_arm64_TEXT_container.bin': dict(
    role='carved __TEXT of a loader that embeds the 322f8877 FAT at offset 0x1D0',
    ios_target='no target ID',
    select_gate='the 5 SystemVersion.plist hits are 1 loader + 2x2 embedded-slice strings, not 5 version-logic '
                'variants; the predicate survives verbatim in both slices (arm64 0xE6FC, arm64e 0x26849)'),
 'nextstage_js/4b987a4f646b3b06_x_nextstage.js': dict(
    role='stage3 WebKit JS (next stage, base64-embedded copy)',
    ios_target='selected per exploit chain by the server, not by a target ID',
    select_gate=''),
 'nextstage_js/1829bafa244522ae_x_nextstage.js': dict(
    role='stage3 WebKit JS (next stage, base64-embedded copy)',
    ios_target='selected per exploit chain by the server, not by a target ID',
    select_gate=''),
}

NEW = ['target_id', 'id_class', 'id_bucket', 'id_subvar', 'target_proc_abi',
       'ios_min', 'ios_max', 'ios_target', 'select_gate', 'role', 'confidence']


def main(write=False):
    top, child = load_facts()
    rows = list(csv.DictReader(open(CSV)))
    fields = list(rows[0].keys()) if rows else []
    out = []
    for r in rows:
        src = (r['source'] or '').replace('.js', '')
        ann = {k: '' for k in NEW}
        if r['out'] in STATIC:
            ann.update(STATIC[r['out']]); ann['confidence'] = 'high'
            ann.setdefault('target_id', '')
        elif src == '7a7d99099b035b2c6512b6ebeeea6df1ede70fbb':
            ann.update(role='payload manifest (0x12345678 config, 19 entries, base "./")',
                       ios_target='index of all targets', confidence='high',
                       select_gate='decrypted with the group.html master key; entry+0x00 = target ID, +0x04 = key, +0x24 = name')
        elif src in top:
            d = decode(top[src]); ann.update({k: d[k] for k in
                ('target_id', 'id_class', 'target_proc_abi', 'ios_min', 'ios_max', 'ios_target', 'select_gate', 'role')})
            ann['id_bucket'] = d['bucket']; ann['id_subvar'] = d['subvar']
            ann['confidence'] = 'high'
        elif src in child:
            d = decode(child[src]); ann.update({k: d[k] for k in
                ('target_id', 'id_class', 'target_proc_abi', 'ios_min', 'ios_max', 'ios_target', 'select_gate', 'role')})
            ann['id_bucket'] = d['bucket']; ann['id_subvar'] = d['subvar']
            # sub_9CB8 would emit class 0x10/0x11 (not 0x02/0xE2) for buckets 0x30/0x40 in THIS
            # bootstrap build, so those two child IDs are not reproducible from this binary alone.
            ann['confidence'] = 'medium' if (child[src] >> 16) & 0xF0 in (0x30, 0x40) else 'high'
        else:
            ann.update(role='unresolved', confidence='low')
        r2 = dict(r); r2.update(ann); out.append(r2)

    if write:
        JSON = os.path.join(EXT, 'manifest.json')
        for path in (CSV, JSON):
            if os.path.exists(path) and not os.path.exists(path + '.orig'):
                shutil.copy2(path, path + '.orig')
        with open(CSV, 'w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=fields + NEW)
            w.writeheader(); w.writerows(out)
        # manifest.json must mirror the CSV; drop the empty strings the CSV needs for
        # fixed columns so the JSON keeps extract.py's "absent key" convention.
        orig_json = json.load(open(JSON + '.orig')) if os.path.exists(JSON + '.orig') else []
        by_out = {r['out']: r for r in orig_json}
        jrows = []
        for r in out:
            base = dict(by_out.get(r['out'], {k: v for k, v in r.items() if k in fields and v != ''}))
            base.update({k: r[k] for k in NEW if r[k] != ''})
            jrows.append(base)
        json.dump(jrows, open(JSON, 'w'), indent=2)
        print(f'[=] wrote {CSV} and {JSON} ({len(out)} rows, +{len(NEW)} columns); '
              f'originals kept as *.orig')
    else:
        for r in out:
            print(f"{r['out'][:52]:52s} {r['target_id']:>12} {r['target_proc_abi']:>7} "
                  f"{r['ios_target'][:58]:58s} {r['confidence']}")
    return out


if __name__ == '__main__':
    main(write='--write' in sys.argv)
