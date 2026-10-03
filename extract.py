#!/usr/bin/env python3.14
# coruna_extract.py — unified extractor for Coruna spyware distribution files
# ============================================================================
# Pipeline:
#   (1) Recursive deobfuscation
#       - entry HTML: new Function(atob("<b64>"))             -> loader
#       - nested atob modules in loader MM map / fgPoij / hPL3On -> recursively flattened
#       - [n,..].map(x=>String.fromCharCode(x^K)).join("")   -> XOR-string recovery
#   (2) Carve artifacts from every flattened layer
#       - Mach-O (thin/fat): find magic at any offset, size it from load commands
#                            (e.g. FAT arm64/arm64e at offset 0x1d0 of a __text container)
#       - ARM64 headerless stub: 'fd 7b bf a9' prologue + dlopen/libdyld import
#       - LZMA container: magic 0x0BEDF00D + [usize] + LZMA
#                        matches compression_decode_buffer(COMPRESSION_LZMA=0x306),
#                          then Mach-O carving on the decompressed output
#       - qbrdr payload: window["qbrdr"]("<b64>") -> dumped as the *encrypted* blob (.enc)
#                        (native stub decrypts at runtime; the key requires stub RE)
#       - next-stage JS: decoded JS such as the qb/native-call framework
#   (3) manifest.csv/json + strings.txt + iocs.txt
#
# Standard library only. Python 3.8+
#   usage: python3 coruna_extract.py <input(zip|dir)> [-o OUTDIR]

import os, re, sys, csv, json, base64, zipfile, hashlib, struct, argparse, lzma

# ── Mach-O carving ──────────────────────────────────────────────────────────
MH = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}
FAT = {0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA}
MAGIC_BYTES = [b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xcf\xfa\xed\xfe',
               b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
               b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca']
_MAGIC_RE = re.compile(b'|'.join(re.escape(m) for m in MAGIC_BYTES))
CPU = {7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64',
       0x0200000c: 'arm64_32'}
FT = {1: 'OBJECT', 2: 'EXECUTE', 6: 'DYLIB', 7: 'DYLINKER', 8: 'BUNDLE',
      0xa: 'DSYM', 0xb: 'KEXT_BUNDLE', 0xc: 'FILESET'}
LC_LINKEDIT = {0x1d, 0x26, 0x29, 0x2b, 0x2e, 0x1e, 0x34}


def _u32(b, o, be): return struct.unpack_from('>I' if be else '<I', b, o)[0]
def _u64(b, o, be): return struct.unpack_from('>Q' if be else '<Q', b, o)[0]


def _cpu(ct, st):
    n = CPU.get(ct, f'0x{ct:08x}')
    if ct == 0x0100000c and (st & 0x00ffffff) == 2:
        n = 'arm64e'
    return n


def parse_thin(d, off):
    if off + 4 > len(d):
        return None, None
    raw = _u32(d, off, False)
    be = raw in (0xCEFAEDFE, 0xCFFAEDFE)
    m = _u32(d, off, be)
    if m not in MH:
        return None, None
    is64 = m == 0xFEEDFACF
    hdr = 32 if is64 else 28
    if off + hdr > len(d):
        return None, None
    ct, st, ft, ncmds, szc = (_u32(d, off+4, be), _u32(d, off+8, be),
                              _u32(d, off+12, be), _u32(d, off+16, be),
                              _u32(d, off+20, be))
    if ncmds > 10000 or szc > 0x2000000:
        return None, None
    end = hdr + szc
    p = off + hdr
    lim = off + hdr + szc
    for _ in range(ncmds):
        if p + 8 > len(d) or p + 8 > lim:
            break
        cmd, csz = _u32(d, p, be), _u32(d, p+4, be)
        if csz < 8:
            break
        try:
            if cmd == 0x1:
                end = max(end, _u32(d, p+32, be) + _u32(d, p+36, be))
            elif cmd == 0x19:
                end = max(end, _u64(d, p+40, be) + _u64(d, p+48, be))
            elif cmd == 0x2:
                end = max(end, _u32(d, p+8, be) + _u32(d, p+12, be) *
                          (16 if is64 else 12), _u32(d, p+16, be) + _u32(d, p+20, be))
            elif cmd in (0x22, 0x80000022):
                for k in range(5):
                    end = max(end, _u32(d, p+8+k*8, be) + _u32(d, p+12+k*8, be))
            elif cmd in LC_LINKEDIT:
                end = max(end, _u32(d, p+8, be) + _u32(d, p+12, be))
        except struct.error:
            pass
        p += csz
    if end <= hdr or off + end > len(d):
        end = min(end, len(d) - off)
        if end <= hdr:
            return None, None
    return end, {'kind': 'thin', 'arch': _cpu(ct, st),
                 'filetype': FT.get(ft, f'0x{ft:x}'), 'bits': 64 if is64 else 32}


def parse_fat(d, off):
    if off + 8 > len(d):
        return None, None
    raw = _u32(d, off, False)
    if raw not in FAT:
        return None, None
    be = raw in (0xBEBAFECA, 0xBFBAFECA)
    m = _u32(d, off, be)
    is64 = m in (0xCAFEBABF, 0xBFBAFECA)
    nfat = _u32(d, off+4, be)
    if nfat == 0 or nfat > 64:
        return None, None
    asz = 32 if is64 else 20
    end = 8 + nfat * asz
    archs = []
    p = off + 8
    for _ in range(nfat):
        if p + asz > len(d):
            return None, None
        ct, st = _u32(d, p, be), _u32(d, p+4, be)
        if is64:
            ao, az = _u64(d, p+8, be), _u64(d, p+16, be)
        else:
            ao, az = _u32(d, p+8, be), _u32(d, p+12, be)
        end = max(end, ao + az)
        archs.append(_cpu(ct, st))
        p += asz
    if off + end > len(d):
        end = len(d) - off
    return end, {'kind': 'fat', 'arch': '+'.join(archs), 'filetype': 'FAT',
                 'bits': 64 if is64 else 32}


def carve_macho(data, source):
    out = []
    for m in _MAGIC_RE.finditer(data):
        off = m.start()
        size, meta = parse_fat(data, off)
        if size is None:
            size, meta = parse_thin(data, off)
        if size and size >= 28:
            meta = dict(meta, source=source, offset=off)
            out.append((data[off:off+size], meta))
    return out


# ── LZMA container (0x0BEDF00D) ─────────────────────────────────────────────
LZMA_MAGIC = struct.pack('<I', 200142861)  # 0x0BEDF00D


def try_lzma(payload):
    """Try to decompress a compression_decode_buffer(COMPRESSION_LZMA) stream in several formats."""
    attempts = [
        dict(format=lzma.FORMAT_XZ),
        dict(format=lzma.FORMAT_ALONE),
        dict(format=lzma.FORMAT_RAW,
             filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6}]),
        dict(format=lzma.FORMAT_RAW,
             filters=[{'id': lzma.FILTER_LZMA1, 'preset': 6}]),
    ]
    for kw in attempts:
        try:
            return lzma.decompress(payload, **kw)
        except Exception:
            continue
    return None


def carve_lzma_containers(data, source):
    """Find [0x0BEDF00D][u32 usize][LZMA] containers and decompress them."""
    out = []
    for m in re.finditer(re.escape(LZMA_MAGIC), data):
        off = m.start()
        if off + 8 > len(data):
            continue
        usize = struct.unpack_from('<I', data, off+4)[0]
        if not (0 < usize < 0x8000000):
            continue
        dec = try_lzma(data[off+8:])
        if dec:
            out.append((dec, {'source': source, 'offset': off,
                              'usize': usize, 'declen': len(dec)}))
    return out


# ── ChaCha20 decryption + container unpack ──────────────────────────────────
# Spec determined by RE of the implant DYLIB (443786da...):
#   - standard ChaCha20, sigma = "expand 32-byte k", 20 rounds (10 double-rounds)
#   - keystream XOR (loop at 0xb044), block counter += 1
#   - state init uses counter=0, nonce=0 (stp xzr,xzr,[sp,#0x80])  <- defaults
#   - key = 32B passed as a function argument (runtime/device/C2 origin -- not in static files)
# Container after decryption:
#   [0xF00DBEEF][u32 count][entry x count]  entry(16B)=[u32 type][u32 res][u32 off][u32 len]
#     - each entry.data (base+off, len) = [0x0BEDF00D][u32 usize][LZMA] (COMPRESSION_LZMA)
F00DBEEF = 0xF00DBEEF
BEDF00D = 0x0BEDF00D

# ── Hardcoded key map (per-module ChaCha20 keys obtained from 0xad8c / 0x9f18 config dumps) ──
# module_hash(40hex) -> 32B key(hex). Used for automatic decryption in the default (no-argument) run.
# When you obtain a new config, add it here (or merge via --c2config/--keymap).
EMBEDDED_KEYS = {
    "1334417664270db20af705f422878c53c8378203": "cab13d34917b6f5bdcfc69d7c668021b735a4d82b05b0918b9e228dc1860988e",
    "1b2cbbde08f8b2330b7400abcb97c9573973e942": "bdff99612a2aa99aef5cd7845d7f0b06a77c36d4f674fab7939799a39b8f78b1",
    "226cbd845c5f470075505392be8693ec6d4f5ba3": "6662406a17f3a38fdbbf9938d3c4c07b649ad22cf6d6f4c00bc9db96910b3817",
    "2a1d692b7b5ba793527b2c14b48db21a3e5d2c5f": "a19b901b47f9dd7b86ca75fa1d25bd4404e9cdd2e2bf56722149fc213434f00e",
    "377bed7460f7538f96bbad7bdc2b8294bdc54599": "388976a2cdce966476ddc0f79249081ec182efc26808beb2e2e456f8c4809535",
    "38af3c8ba461079a0edc83585023f76843066dcf": "50a323f335f2bf4634b8f13526dc46f73d6ae15d4960d1f72e601aa4e733a7ec",
    "4612aa650e60e2974a9ec37bbf922c79635b493a": "85ab5908ceb1981df3449b52155a5026561c51d6f9f599acc99c5203b14733eb",
    "4800048658463f971e752ff93c1767e9ae7f3431": "6c682a65deb7cf020dd640d130a2a73e9442ccddc441520c951620a4142605ad",
    "4817ea8063eb4480e915f1a4479c62ec774f52ce": "b252669de4b4adc34114fdf10d75f66b3efad6280f4fcd19603f6fac5873ede2",
    "5258f6e3eef3eda249179aa1122b50b03cbeea18": "176f3b0d80c6c94f5bcc3e638185d1a4a057a859141b569f877468cc7bd7c149",
    "5e89f83ec50c6223d664d3f3260ef874a3d6d796": "be7efb67c5b39656f00f03b5a06593bf41bd760e5280a887f0a701226f39c3c8",
    "667fa543143862135ab6b41740421a4752799863": "04da244132e7096db7a58bd0d683088df7e09b0cf8ddd39af0210b072484c56d",
    "72a5ac816709f9c331f2b3afb76cd3d96517ea14": "c02c657bb22d6cfc6aed70143f1fc8fbd44f33dbe6e12979d10c7891dcfc25c7",
    # Master key (manifest 7a7d99) -- group.html's fqMaGkN4([8xu32]) encoded as UTF-16LE (= <8I>).
    # Decrypting 7a7d99 with this key yields the remaining 19 per-file keys (static derivation).
    "7a7d99099b035b2c6512b6ebeeea6df1ede70fbb": "b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676",
    "7a1cef00016b950be42f5288ead21fa6fccc3107": "8360789e772f55126e9114dc7965d3162d6b7a781ddfa69be0971c66f04e6045",
    "980c77f1747afa9ac1fa5f8fbfb9e6663e9f82bb": "338bf220589af21d44e4dda167fab47c99040da951c40406ff99b5c4cc48735e",
    "a159973efdd00dd988fec1d707338545d9487b6a": "7ae216d3b4ba8b417b1784f2d0e8f10c40377819345f8946974420fdd1fd111f",
    "a78a94196b5d2c95865f6a8423a6b8eb86d07c6c": "e6542d26109c5c3aa4f33c9ee07d69dc58ef66e81a7c20c2447cff7fe9f45a0c",
    "ae7efd66ecde9e964cfe92f64e9b6461fce38f28": "fdd8b3940d2a06b0229d814e874095fd1fa87cb53db4699ba9dd8dd7370cf8cc",
    "b442ab113b829ff8c7bf34afa4d2d997889f308f": "230ddaa380a7899e52be22cc926a4b7609303e14c3ed55d59049d3b20ee12974",
    "c8a14d79a27953242d60243ee2f505a85d9232cc": "3cb781d9c1ade5c3b54606839baa51f5c5751f73f0cd055fc101e41d467403d7",
    "e9f898587620186e31119fbf32660f26c1e048e0": "58199343c3811b01adda525bc08fcf135c6369fb3bdc3d52ca2374491e789f48",
    "f4120dc6717a489435d86943472c5a2444aac8e6": "a6244c09c0588cf126ad727f75a647132543239c8b8fff5d362d56b616752327",
    "f8a86cf368fdbbe294813926a2a229df041eb758": "7da5f7d73e652aa782c89a883c27d0898affddf5d13b5914423a66a15ad3b319",
}


def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _qr(s, a, b_, c, d):
    s[a] = (s[a] + s[b_]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b_] = _rotl(s[b_] ^ s[c], 12)
    s[a] = (s[a] + s[b_]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b_] = _rotl(s[b_] ^ s[c], 7)


def chacha20_xor(key, data, counter=0, nonce=b'\x00' * 12):
    """RFC8439 ChaCha20 keystream XOR. key=32B, nonce=12B. (verified against RFC test vectors)"""
    assert len(key) == 32 and len(nonce) == 12
    out = bytearray(); i = 0
    kw = list(struct.unpack('<8I', key)); nw = list(struct.unpack('<3I', nonce))
    while i < len(data):
        st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + kw + \
             [counter + i // 64] + nw
        w = st[:]
        for _ in range(10):
            _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13)
            _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
            _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12)
            _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
        ks = struct.pack('<16I', *[(w[j] + st[j]) & 0xffffffff for j in range(16)])
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        i += 64
    return bytes(out)


def unpack_container(dec):
    """Decrypted buffer -> [Mach-O bytes...]. Handles both the F00DBEEF manifest and a direct 0BEDF00D."""
    machos = []
    if len(dec) >= 8 and struct.unpack_from('<I', dec, 0)[0] == F00DBEEF:
        count = struct.unpack_from('<I', dec, 4)[0]
        p = 8
        for _ in range(min(count, 4096)):
            if p + 16 > len(dec):
                break
            etype, _res, off, ln = struct.unpack_from('<IIII', dec, p); p += 16
            blob = dec[off:off + ln]
            machos += _unpack_entry(blob)
    else:
        machos += _unpack_entry(dec)
    return machos


def _unpack_entry(blob):
    out = []
    if len(blob) >= 8 and struct.unpack_from('<I', blob, 0)[0] == BEDF00D:
        raw = try_lzma(blob[8:])
        if raw:
            found = carve_macho(raw, 'decrypted')
            out += [mo for mo, _ in found] if found else [raw]
    else:
        for mo, _ in carve_macho(blob, 'decrypted'):
            out.append(mo)
    return out


def decrypt_payloads(encdir, outdir, key, nonce, counter):
    """ChaCha20-decrypt every payloads_encrypted/*.enc -> unpack -> save Mach-O."""
    import glob
    os.makedirs(os.path.join(outdir, 'decrypted'), exist_ok=True)
    os.makedirs(os.path.join(outdir, 'decrypted_raw'), exist_ok=True)
    files = sorted(glob.glob(os.path.join(encdir, '*.enc')))
    print(f"[*] decrypting {len(files)} .enc files (ChaCha20 key={key.hex()[:16]}... "
          f"nonce={nonce.hex()} ctr={counter})")
    n_ok = n_macho = 0
    for f in files:
        enc = open(f, 'rb').read()
        dec = chacha20_xor(key, enc, counter, nonce)
        base = os.path.basename(f)[:-4]
        ok = struct.unpack_from('<I', dec, 0)[0] in (F00DBEEF, BEDF00D)
        # always keep the raw decrypted output (for verification/further analysis)
        open(os.path.join(outdir, 'decrypted_raw', base + '.bin'), 'wb').write(dec)
        if ok:
            n_ok += 1
        machos = unpack_container(dec)
        for i, mo in enumerate(machos):
            h = hashlib.sha256(mo).hexdigest()[:16]
            fn = f"{base}_{i}_{h}.macho"
            open(os.path.join(outdir, 'decrypted', fn), 'wb').write(mo)
            n_macho += 1
        flag = 'OK' if ok else 'magic mismatch (check key/nonce)'
        print(f"  [{flag:>20}] {base[:16]} dec[:4]={dec[:4].hex()} "
              f"→ macho×{len(machos)}")
    print(f"[=] magic confirmed {n_ok}/{len(files)} - extracted {n_macho} Mach-O "
          f"-> {outdir}/decrypted/")
    if n_ok == 0:
        print("[!] all magic mismatched: this key/nonce does not decrypt. "
              "Keys originate at runtime (device+C2), so obtain them via device dump/Frida.")


def parse_c2_config(data):
    """Parse a C2 config (0x12345678) -> {module_name: key_bytes}.

    Layout confirmed by RE (0x9f18):
      [+0x00] u32 magic=0x12345678   [+0x108] u32 count
      [+0x10c] entry[count], each 0x64B: [+0x00]u32 id [+0x04]32B key [+0x24]name(64B)

    Parses every config even when several are concatenated in one file (each starts with the magic).
    (e.g. a file accumulated per hit via LLDB `memory read --append`)
    """
    out = {}
    magic = struct.pack('<I', 0x12345678)
    offs = [m.start() for m in re.finditer(re.escape(magic), data)]
    if not offs:
        return out
    for base in offs:
        if base + 0x10c > len(data):
            continue
        count = struct.unpack_from('<I', data, base + 0x108)[0]
        if not (0 < count < 8192):
            continue
        p = base + 0x10c
        for _ in range(count):
            if p + 0x64 > len(data):
                break
            key = data[p + 4:p + 4 + 32]
            name = data[p + 0x24:p + 0x64].split(b'\x00')[0].decode('latin1', 'replace')
            if name and len(key) == 32:
                out[name] = key
            p += 0x64
    return out


def derive_master_key(texts):
    """group.html's fqMaGkN4([8xu32]) array -> master ChaCha20 key (32B).
    Equivalent to encoding each uint32 as UTF-16LE (= little-endian 4 bytes).
    """
    pat = re.compile(r'fqMaGkN4\(\[\s*((?:\d+\s*,\s*){7}\d+)\s*\]\)')
    for t in texts:
        for m in pat.finditer(t):
            nums = [int(x) for x in m.group(1).split(',')]
            if len(nums) == 8 and all(0 <= n < 2**32 for n in nums):
                return struct.pack('<8I', *nums)
    return None


def manifest_keys_from_capture(texts, encdir, recs):
    """Fully static self-contained decryption: HTML master key -> decrypt 7a7d99 manifest -> 19 per-file keys.

    Returns: {module_hash: key_bytes}. (no device / runtime config required)
    """
    import glob
    master = derive_master_key(texts) or bytes.fromhex(
        EMBEDDED_KEYS.get("7a7d99099b035b2c6512b6ebeeea6df1ede70fbb", ""))
    if not master or len(master) != 32:
        return {}
    # locate the 7a7d99 manifest blob
    manifest_hash = "7a7d99099b035b2c6512b6ebeeea6df1ede70fbb"
    blob = None
    for f in glob.glob(os.path.join(encdir, '*.enc')):
        if recs.get(os.path.basename(f), '').startswith(manifest_hash):
            blob = open(f, 'rb').read(); break
    if blob is None:
        return {}
    dec = chacha20_xor(master, blob)
    if struct.unpack_from('<I', dec, 0)[0] != BEDF00D:
        return {}
    raw = try_lzma(dec[8:])
    if not raw or struct.unpack_from('<I', raw, 0)[0] != F00DBEEF:
        return {}
    # F00DBEEF manifest: 0x64B entries, key@+0x08(32B), name@+0x28(48B)
    out = {}
    for m in re.finditer(rb'([0-9a-f]{40})\.min\.js', raw):
        name_off = m.start()
        key = raw[name_off - 0x20:name_off]   # name@entry+0x28, key@entry+0x08 -> name-0x20
        if len(key) == 32:
            out[m.group(1).decode()] = key
    return out


def child_keys_from_decrypted(outdir):
    """Second static derivation stage -> {module_hash: key_bytes}.

    Every decrypted stage-3 bundle carries a nested 0x12345678 config as its last
    type-0x07 entry (0x1D4 B = 0x10c header + 2 x 0x64 entries).  Those entries hold
    the per-file ChaCha20 keys of the second-level modules the bundle chains to, in the
    same layout parse_c2_config() uses: [+0x00]u32 id [+0x04]32B key [+0x24]name(64B).
    Harvesting them resolves the 6 blobs that the manifest alone cannot (0d42ae58,
    1bda4348, a0d313c0, b15eaa92, c4e0a45c, cb0b1926) -- still fully static.
    """
    import glob
    out = {}
    for f in sorted(glob.glob(os.path.join(outdir, 'decrypted_raw', '*.bin'))):
        d = open(f, 'rb').read()
        if len(d) >= 8 and struct.unpack_from('<I', d, 0)[0] == BEDF00D:
            d = try_lzma(d[8:]) or b''
        if len(d) < 8 or struct.unpack_from('<I', d, 0)[0] != F00DBEEF:
            continue
        count = struct.unpack_from('<I', d, 4)[0]
        p = 8
        for _ in range(min(count, 4096)):
            if p + 16 > len(d):
                break
            _et, _res, off, ln = struct.unpack_from('<IIII', d, p); p += 16
            blob = d[off:off + ln]
            if len(blob) >= 8 and struct.unpack_from('<I', blob, 0)[0] == BEDF00D:
                blob = try_lzma(blob[8:]) or b''
            if len(blob) < 0x10c or struct.unpack_from('<I', blob, 0)[0] != 0x12345678:
                continue
            n = struct.unpack_from('<I', blob, 0x108)[0]
            q = 0x10c
            for _ in range(min(n, 4096)):
                if q + 0x64 > len(blob):
                    break
                e = blob[q:q + 0x64]; q += 0x64
                h = e[0x24:0x64].split(b'\x00')[0].decode('latin1', 'replace').split('.')[0]
                if len(h) == 40 and all(c in '0123456789abcdef' for c in h):
                    out[h] = e[4:36]
    return out


def decrypt_with_keylist(encdir, outdir, keys, nonce=b'\x00' * 12, counter=0, known=()):
    """Auto-assign a collected key list (each 64hex) to blobs and decrypt.
    Since each blob has a different key, every key is tried against all
    unresolved blobs via a signature oracle and assigned once confirmed.
    (No name matching needed -- just collect keys at 0xad8c.)

    known: blob basenames a previous pass already resolved; they are counted toward
    the summary but not decrypted again (used by the stage-2 harvest in main())."""
    import glob
    os.makedirs(os.path.join(outdir, 'decrypted'), exist_ok=True)
    os.makedirs(os.path.join(outdir, 'decrypted_raw'), exist_ok=True)
    blobs = [(os.path.basename(f)[:-4], open(f, 'rb').read())
             for f in sorted(glob.glob(os.path.join(encdir, '*.enc')))]
    fast = (nonce == b'\x00' * 12 and counter == 0)
    need = {}
    if fast:
        for bi, (_, b) in enumerate(blobs):
            for mb in (struct.pack('<I', F00DBEEF), struct.pack('<I', BEDF00D)):
                need.setdefault(bytes(a ^ c for a, c in zip(b[:4], mb)), []).append(bi)
    done = {bi: b'' for bi, (nm, _) in enumerate(blobs) if nm in set(known)}
    n_macho = 0
    for key in keys:
        if len(key) != 32:
            continue
        targets = (need.get(_chacha_block0_head4(key), [])
                   if fast else range(len(blobs)))
        for bi in targets:
            if bi in done:
                continue
            name, blob = blobs[bi]
            dec = chacha20_xor(key, blob, counter, nonce)
            if struct.unpack_from('<I', dec, 0)[0] not in (F00DBEEF, BEDF00D):
                continue
            done[bi] = key
            open(os.path.join(outdir, 'decrypted_raw', name + '.bin'), 'wb').write(dec)
            machos = unpack_container(dec)
            for j, mo in enumerate(machos):
                h = hashlib.sha256(mo).hexdigest()[:16]
                open(os.path.join(outdir, 'decrypted',
                                  f"{name}_{j}_{h}.macho"), 'wb').write(mo)
                n_macho += 1
            print(f"  [OK] {name[:16]} key={key.hex()[:16]}... -> macho x{len(machos)}")
    print(f"[=] decrypted {len(done)}/{len(blobs)} blobs - {n_macho}{' new' if known else ''} "
          f"Mach-O -> {outdir}/decrypted/")
    miss = [blobs[i][0] for i in range(len(blobs)) if i not in done]
    if miss:
        print(f"[!] {len(miss)} unresolved: need to collect more keys. e.g. {miss[0][:16]} ...")


def decrypt_with_keymap(encdir, outdir, keymap, nonce=b'\x00' * 12, counter=0):
    """Decrypt/unpack each blob with its own key via a module->key mapping (JSON).

    keymap: { "<module_hash | .js | .enc name>": "<64hex key>", ... }
    (built by collecting x0[0:32]=key and x0[0x20:]=module name at 0xad8c via LLDB/Frida)
    blob->key matching: compare the manifest source (module .js) or .enc name against keymap keys.
    """
    import glob
    os.makedirs(os.path.join(outdir, 'decrypted'), exist_ok=True)
    os.makedirs(os.path.join(outdir, 'decrypted_raw'), exist_ok=True)
    recs = {}
    mj = os.path.join(outdir, 'manifest.json')
    if os.path.exists(mj):
        for r in json.load(open(mj)):
            if 'payloads_enc' in r.get('out', ''):
                recs[r['out'].split('/')[-1]] = r.get('source', '')
    # normalize the keymap: index every key as a lowercase hex chunk
    norm = {}
    for k, v in keymap.items():
        kk = os.path.basename(k).lower()
        for cand in {kk, kk.replace('.min.js', '').replace('.js', '').replace('.enc', '')}:
            norm[cand] = bytes.fromhex(v)

    def lookup(encname, source):
        keys = {encname.lower(), encname.lower().replace('.enc', ''),
                os.path.basename(source).lower(),
                os.path.basename(source).lower().replace('.min.js', '').replace('.js', '')}
        for k in keys:
            if k in norm:
                return norm[k]
        # partial match (when the module hash is contained in source)
        for nk, nv in norm.items():
            if len(nk) >= 16 and (nk in source.lower() or nk in encname.lower()):
                return nv
        return None

    files = sorted(glob.glob(os.path.join(encdir, '*.enc')))
    n_ok = n_macho = n_nokey = 0
    print(f"[*] keymap decryption: {len(files)} .enc files, {len(keymap)} keys")
    for f in files:
        enc = os.path.basename(f)
        key = lookup(enc, recs.get(enc, ''))
        if not key or len(key) != 32:
            n_nokey += 1
            print(f"  [no-key] {enc[:16]} (source={recs.get(enc,'?')[:20]})")
            continue
        dec = chacha20_xor(key, open(f, 'rb').read(), counter, nonce)
        magic = struct.unpack_from('<I', dec, 0)[0]
        base = enc[:-4]
        if magic not in (F00DBEEF, BEDF00D):
            print(f"  [fail] {enc[:16]} magic={magic:#010x} (key/nonce mismatch)")
            continue
        n_ok += 1
        open(os.path.join(outdir, 'decrypted_raw', base + '.bin'), 'wb').write(dec)
        machos = unpack_container(dec)
        for j, mo in enumerate(machos):
            h = hashlib.sha256(mo).hexdigest()[:16]
            open(os.path.join(outdir, 'decrypted',
                              f"{base}_{j}_{h}.macho"), 'wb').write(mo)
            n_macho += 1
        print(f"  [OK]  {enc[:16]} magic={magic:#010x} -> macho x{len(machos)}")
    print(f"[=] decrypted {n_ok}/{len(files)} - {n_macho} Mach-O - {n_nokey} without key "
          f"-> {outdir}/decrypted/")
    if n_nokey:
        print(f"[!] {n_nokey} had no key. Collect the remaining (module,key) pairs via the "
              f"0xad8c hook and add them to the keymap (each blob has a different key).")


def _chacha_block0_head4(key):
    """First-block keystream[0:4] with ctr=0, nonce=0 (for the fast oracle)."""
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + \
        list(struct.unpack('<8I', key)) + [0, 0, 0, 0]
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13)
        _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12)
        _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack('<I', (w[0] + st[0]) & 0xffffffff)


def _decrypt_and_confirm(key, data, nonce, counter):
    """Confirm via container magic / Mach-O unpack after decryption. Returns (dec, machos) on success."""
    dec = chacha20_xor(key, data, counter, nonce)
    if struct.unpack_from('<I', dec, 0)[0] not in (F00DBEEF, BEDF00D):
        return None
    return dec, unpack_container(dec)


def _blob_key_trials(blob, src_hash):
    """Generator of (tag, key, nonce, counter, data) candidates derivable from the blob.
    Embedded keys (prefix/suffix/offset) + nonce variants + slice SHA-256.
    data is the actual ciphertext to decrypt (excluding the key bytes)."""
    Z = b'\x00' * 12
    n = len(blob)
    if n >= 44:
        yield 'embed-prepend', blob[:32], Z, 0, blob[32:]
        yield 'embed-prepend+nonce', blob[:32], blob[32:44], 0, blob[44:]
        yield 'embed-append', blob[-32:], Z, 0, blob[:-32]
        yield 'embed-append+nonce', blob[-32:], blob[-44:-32], 0, blob[:-44]
    # embedded key at every offset (4B step, front region only): ciphertext starts after the key
    for off in range(0, min(n - 36, 8192), 4):
        yield f'embed@{off}', blob[off:off + 32], Z, 0, blob[off + 32:]
    # SHA-256 derivation: the whole blob is ciphertext
    for i, s in enumerate((blob, blob[:0x10c], blob[:64], blob[-64:])):
        yield f'sha256-slice#{i}', hashlib.sha256(s).digest(), Z, 0, blob
    if src_hash:
        yield 'sha256-modhash-ascii', hashlib.sha256(src_hash.encode()).digest(), Z, 0, blob
        try:
            yield 'sha256-modhash-bytes', hashlib.sha256(bytes.fromhex(src_hash)).digest(), Z, 0, blob
        except ValueError:
            pass


def search_keys(encdir, outdir, keysources, step=1, seeds=None,
                nonce=b'\x00' * 12, counter=0):
    """Signature-verified key search + decryption of all payloads.

    Oracle: if a candidate key decrypts a blob into something with a
    container/Mach-O signature, that key is correct. Per RE, Coruna decrypted
    output must start at offset 0 with 0xF00DBEEF (manifest) or 0x0BEDF00D
    (LZMA) -> used as the first-stage oracle, confirmed by full unpack
    (-> Mach-O carve). Each blob has a different key, so matching is independent.

    Candidate keys = (1) derived from the blob itself (embedded / slice SHA-256)
    (2) 32B sliding window over keysources files  (3) SHA-256 of seeds.
    All are tried per blob.
    """
    import glob
    os.makedirs(os.path.join(outdir, 'decrypted'), exist_ok=True)
    os.makedirs(os.path.join(outdir, 'decrypted_raw'), exist_ok=True)
    recs = {}
    mj = os.path.join(outdir, 'manifest.json')
    if os.path.exists(mj):
        for r in json.load(open(mj)):
            if 'payloads_enc' in r.get('out', ''):
                recs[r['out'].split('/')[-1]] = r.get('source', '').replace('.js', '')
    blobs = [(os.path.basename(f)[:-4], open(f, 'rb').read())
             for f in sorted(glob.glob(os.path.join(encdir, '*.enc')))]
    if not blobs:
        print(f"[!] no .enc files in {encdir}"); return {}

    # fast first-stage oracle for external/binary key candidates: keystream[0:4] match map
    magics = {'F00DBEEF': struct.pack('<I', F00DBEEF),
              '0BEDF00D': struct.pack('<I', BEDF00D)}
    need_map = {}
    for bi, (_, b) in enumerate(blobs):
        for mn, mb in magics.items():
            need_map.setdefault(bytes(a ^ c for a, c in zip(b[:4], mb)),
                                []).append((bi, mn))

    found = {}   # blob_idx -> (tag, key, nonce, counter, machos)

    def accept(bi, tag, key, nn, ctr, data):
        if bi in found:
            return
        name, _blob = blobs[bi]
        r = _decrypt_and_confirm(key, data, nn, ctr)
        if not r:
            return
        dec, machos = r
        found[bi] = (tag, key, nn, ctr, machos)
        open(os.path.join(outdir, 'decrypted_raw', name + '.bin'), 'wb').write(dec)
        for j, mo in enumerate(machos):
            h = hashlib.sha256(mo).hexdigest()[:16]
            open(os.path.join(outdir, 'decrypted',
                              f"{name}_{j}_{h}.macho"), 'wb').write(mo)
        print(f"  [KEY] {name[:16]} <- {tag} key={key.hex()} -> macho x{len(machos)}")

    # (1) candidates derived from the blob itself (embedded/derived) -- per blob
    print(f"[*] stage 1: trying blob-derived keys (embedded/SHA-256) ...")
    for bi, (name, blob) in enumerate(blobs):
        for tag, key, nn, ctr, data in _blob_key_trials(blob, recs.get(name, '')):
            if nn == b'\x00' * 12 and ctr == 0 and len(data) >= 4:
                # fast pre-filter: based on the first 4 bytes of data
                needs = {bytes(a ^ c for a, c in zip(data[:4], mb))
                         for mb in magics.values()}
                if _chacha_block0_head4(key) not in needs:
                    continue
            accept(bi, tag, key, nn, ctr, data)
            if bi in found:
                break

    # (2) 32B window over external/binary key sources (default nonce/ctr) -- fast oracle then confirm
    remaining = [bi for bi in range(len(blobs)) if bi not in found]
    if remaining and keysources:
        print(f"[*] stage 2: 32B window over {len(keysources)} key sources (step={step}) "
              f"-- {len(remaining)} unresolved blobs ...")
        checked = 0
        for src in keysources:
            try:
                data = open(src, 'rb').read()
            except Exception:
                continue
            for i in range(0, max(0, len(data) - 32), step):
                key = data[i:i + 32]
                checked += 1
                hit = need_map.get(_chacha_block0_head4(key))
                if not hit:
                    continue
                for bi, _mn in hit:
                    accept(bi, f'{os.path.basename(src)}@{i}', key,
                           b'\x00' * 12, 0, blobs[bi][1])
        print(f"    (checked {checked} windows)")

    # (3) SHA-256 of seeds
    for s in (seeds or []):
        for key in (hashlib.sha256(s).digest(), (s + b'\x00' * 32)[:32]):
            hit = need_map.get(_chacha_block0_head4(key))
            if hit:
                for bi, _mn in hit:
                    accept(bi, f'seed:{s!r}', key, b'\x00' * 12, 0, blobs[bi][1])

    n_macho = sum(len(v[4]) for v in found.values())
    print(f"[=] keys found {len(found)}/{len(blobs)} blobs - extracted {n_macho} Mach-O "
          f"-> {outdir}/decrypted/")
    if len(found) < len(blobs):
        miss = len(blobs) - len(found)
        print(f"[!] {miss} blobs unresolved: their keys are not in this capture (runtime origin). "
              f"Retry by passing a device memory dump / C2 config via --keysource.")
    return found


def recover_keystream(encdir):
    """Recover the keystream via known-plaintext (F00DBEEF) when the keystream is reused (same key+nonce).
    Does not apply to the Coruna capture (each blob has a different key), but kept for similar samples."""
    import glob
    files = sorted(glob.glob(os.path.join(encdir, '*.enc')))
    heads = [open(f, 'rb').read()[:4] for f in files]
    kp = struct.pack('<I', F00DBEEF)
    ks0 = [bytes(a ^ b for a, b in zip(h, kp)) for h in heads]
    same = len(set(ks0)) == 1
    print(f"[*] unique keystream[0:4] values across blobs: {len(set(ks0))} "
          f"({'identical -> keystream reuse possible' if same else 'distinct -> different key per blob, no reuse'})")
    return same


# ── Recursive deobfuscation ─────────────────────────────────────────────────
_XORSTR = re.compile(
    r'\[([\d,\s]+)\]\.map\(\s*(\w+)\s*=>\s*\{?\s*return\s+'
    r'String\.fromCharCode\(\s*\2\s*\^\s*(\d+)\s*\)\s*;?\s*\}?\s*\)\.join\(""\)')
_B64TOK = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_JS_HEAD = re.compile(r'^\s*(let |const |var |function |window\[|globalThis|'
                      r'\(function|!function|return |class )')


def resolve_xor(src):
    found = []

    def repl(m):
        nums = [int(x) for x in m.group(1).split(',') if x.strip()]
        k = int(m.group(3))
        s = ''.join(chr(n ^ k) for n in nums)
        found.append(s)
        return f'{m.group(0)}/*= {s.replace("*/", "*\\/")!r} */'
    return _XORSTR.sub(repl, src), found


def flatten(text, layers, seen, depth=0):
    """Recursively decode base64->JS layers and accumulate them into layers."""
    if depth > 14:
        return
    for m in _B64TOK.finditer(text):
        b = m.group()
        key = hash(b)
        if key in seen:
            continue
        seen.add(key)
        try:
            dec = base64.b64decode(b + '=' * (-len(b) % 4)).decode('latin1')
        except Exception:
            continue
        if _JS_HEAD.match(dec):
            layers.append(dec)
            flatten(dec, layers, seen, depth + 1)


def iter_inputs(path):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in files:
                if fn.endswith(('.js', '.html')):
                    yield fn, open(os.path.join(root, fn),
                                   encoding='latin1').read()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if i.filename.endswith(('.js', '.html')):
                    yield os.path.basename(i.filename), z.read(i).decode('latin1')
    else:
        yield os.path.basename(path), open(path, encoding='latin1').read()


_IOC = re.compile(r'https?://|/System/|/usr/lib|\.dylib|\.framework|__ZN|'
                  r'compression_|libcompression|CV3D|IOSurface|mach_|task_for|'
                  r'dlopen|dlsym|GET|POST|User-Agent', re.I)
_QBRDR = re.compile(r'window\["qbrdr"\]\("([A-Za-z0-9+/=]+)"\)')


def main():
    ap = argparse.ArgumentParser(description='Coruna unified extractor (deobf + Mach-O carve + ChaCha20 decryption)')
    ap.add_argument('input', help='zip/dir (extract mode) or an existing outdir (decrypt mode)')
    ap.add_argument('-o', '--outdir', default='coruna_out')
    ap.add_argument('--chacha-key', metavar='HEX',
                    help='32B ChaCha20 key (hex). If given, decrypt/unpack payloads_encrypted/')
    ap.add_argument('--nonce', metavar='HEX', default='00' * 12,
                    help='12B nonce (hex). Default 0 (per binary RE)')
    ap.add_argument('--counter', type=int, default=0, help='block counter start value. Default 0')
    ap.add_argument('--config-dir', metavar='DIR',
                    help='merge and use all config dumps (*.bin) in the directory')
    ap.add_argument('--c2config', metavar='FILE', action='append', default=[],
                    help='C2 config (0x12345678) binary. Repeatable (merges multiple hits). '
                         'Collects keys from each config\'s [id][key][name] entries to decrypt all blobs')
    ap.add_argument('--keys', metavar='FILE',
                    help='collected key list (64hex per line). Auto-assigned to blobs for decryption')
    ap.add_argument('--keymap', metavar='JSON',
                    help='module->key mapping JSON. Decrypt each blob with its dedicated key '
                         '(result of collecting at the 0xad8c hook)')
    ap.add_argument('--recover-keystream', action='store_true',
                    help='diagnose keystream reuse (known-plaintext F00DBEEF)')
    ap.add_argument('--search-keys', action='store_true',
                    help='signature-verified key search (accept if the decryption is a container/Mach-O)')
    ap.add_argument('--keysource', action='append', default=[], metavar='FILE',
                    help='key material file (memory dump / C2 config, etc.). Repeatable. '
                         'If omitted, all extracted binaries are used as sources')
    ap.add_argument('--step', type=int, default=1,
                    help='sliding-window step (bytes) for key search. Default 1')
    args = ap.parse_args()
    O = args.outdir

    # ── decryption / key-search only mode ──
    if args.config_dir:
        import glob as _glob
        args.c2config = list(args.c2config) + sorted(
            _glob.glob(os.path.join(args.config_dir, '*.bin')))
    if (args.chacha_key or args.recover_keystream or args.search_keys
            or args.keymap or args.keys or args.c2config):
        base = args.input if os.path.isdir(args.input) else O
        encdir = os.path.join(base, 'payloads_encrypted')
        if not os.path.isdir(encdir):
            encdir = args.input
        if args.c2config:
            merged = {}
            for cf in args.c2config:
                cfg = parse_c2_config(open(cf, 'rb').read())
                merged.update(cfg)
                print(f"[*] {os.path.basename(cf)}: {len(cfg)} entries")
            # merge with a previously accumulated keymap if present (accumulates across sessions)
            kmpath = os.path.join(base, 'coruna_keymap.json')
            acc = {}
            if os.path.exists(kmpath):
                acc = json.load(open(kmpath))
            acc.update({k: v.hex() for k, v in merged.items()})
            json.dump(acc, open(kmpath, 'w'), indent=2)
            print(f"[*] accumulated keymap: {len(acc)} (module->key) -> {kmpath}")
            # both name matching and signature auto-assignment
            decrypt_with_keymap(encdir, base, acc,
                                bytes.fromhex(args.nonce), args.counter)
            decrypt_with_keylist(encdir, base, [bytes.fromhex(v) for v in acc.values()],
                                 bytes.fromhex(args.nonce), args.counter)
        if args.keys:
            keys = []
            for line in open(args.keys):
                h = line.strip().replace('0x', '').replace(' ', '')
                if len(h) == 64:
                    try:
                        keys.append(bytes.fromhex(h))
                    except ValueError:
                        pass
            decrypt_with_keylist(encdir, base, keys,
                                 bytes.fromhex(args.nonce), args.counter)
        if args.keymap:
            km = json.load(open(args.keymap))
            decrypt_with_keymap(encdir, base, km,
                                bytes.fromhex(args.nonce), args.counter)
        if args.recover_keystream:
            recover_keystream(encdir)
        if args.search_keys:
            import glob
            ks = args.keysource or (glob.glob(os.path.join(base, 'macho', '*.macho')) +
                                    glob.glob(os.path.join(base, 'native', '*.bin')) +
                                    glob.glob(os.path.join(base, 'nextstage_js', '*.js')))
            seeds = [b'coruna', b'Coruna', b'8df9.cc', b'qbrdr',
                     b'expand 32-byte k', struct.pack('<I', 0x12345678)]
            search_keys(encdir, base, ks, args.step, seeds)
        if args.chacha_key:
            key = bytes.fromhex(args.chacha_key)
            nonce = bytes.fromhex(args.nonce)
            if len(key) != 32:
                ap.error('--chacha-key must be exactly 32 bytes (64 hex)')
            if len(nonce) != 12:
                ap.error('--nonce must be 12 bytes (24 hex)')
            decrypt_payloads(encdir, base, key, nonce, args.counter)
        return
    for sub in ('macho', 'native', 'nextstage_js', 'payloads_encrypted', 'modules'):
        os.makedirs(os.path.join(O, sub), exist_ok=True)

    # 1) load + recursive flatten
    raw_files = list(iter_inputs(args.input))
    layers = []
    seen = set()
    for name, text in raw_files:
        layers.append(text)
        flatten(text, layers, seen)
    print(f"[*] {len(raw_files)} inputs / {len(layers)} flattened layers")

    # 2) XOR-string recovery + IOC collection (across all layers)
    all_strings = set()
    for L in layers:
        _, strs = resolve_xor(L)
        all_strings.update(strs)

    # 3) artifact carving
    records = []
    seen_sha = set()

    def save(subdir, blob, meta, ext):
        h = hashlib.sha256(blob).hexdigest()
        if h in seen_sha:
            return
        seen_sha.add(h)
        arch = meta.get('arch', 'x')
        ft = meta.get('filetype', meta.get('type', 'bin'))
        fn = f"{h[:16]}_{arch}_{ft}{ext}"
        open(os.path.join(O, subdir, fn), 'wb').write(blob)
        records.append(dict(out=f'{subdir}/{fn}', sha256=h, size=len(blob), **meta))
        print(f"[+] {subdir:20} {arch:<12} {ft:<8} {len(blob):>9}B  "
              f"{meta.get('source','')[:22]}@0x{meta.get('offset',0):x}")

    # 3a) carve Mach-O / LZMA / native from decoded base64 blobs + original text
    decoded_blobs = []
    for L in layers:
        for m in re.finditer(r'[A-Za-z0-9+/]{200,}={0,2}', L):
            b = m.group()
            try:
                decoded_blobs.append(base64.b64decode(b + '=' * (-len(b) % 4)))
            except Exception:
                pass
    for blob in decoded_blobs:
        for mo, meta in carve_macho(blob, 'embedded'):
            save('macho', mo, meta, '.macho')
        for dec, meta in carve_lzma_containers(blob, 'embedded'):
            meta['type'] = 'LZMA_out'
            # carve Mach-O again from the decompressed output
            inner = carve_macho(dec, 'lzma_out')
            if inner:
                for mo, m2 in inner:
                    save('macho', mo, m2, '.macho')
            else:
                save('native', dec, meta, '.bin')
        # ARM64 headerless stub
        if blob[:4] == b'\xfd\x7b\xbf\xa9' and (b'dlopen' in blob[:2048] or
                                                b'libdyld' in blob[:2048]):
            save('native', blob, {'arch': 'arm64', 'type': 'ARM64_stub'}, '.bin')
        # __text segment container (preserved as-is too)
        if blob[:6] == b'__text':
            save('native', blob, {'arch': 'arm64', 'type': 'TEXT_container'}, '.bin')

    # 3b) next-stage JS
    for blob in decoded_blobs:
        head = blob[:16]
        if head[:8] == b'function' or head[:6] == b'class ' or \
           (head[:4] == b'let ' and b'.call(' in blob[:4000]):
            save('nextstage_js', blob, {'type': 'nextstage'}, '.js')

    # 3c) qbrdr encrypted payload (from original modules only)
    for name, text in raw_files:
        mm = _QBRDR.search(text)
        if mm:
            enc = base64.b64decode(mm.group(1) + '=' * (-len(mm.group(1)) % 4))
            save('payloads_encrypted', enc,
                 {'type': 'qbrdr_enc', 'source': name}, '.enc')

    # 3d) save readable modules (with XOR-recovered annotations)
    for name, text in raw_files:
        if name.endswith('.js'):
            ann, _ = resolve_xor(text)
            open(os.path.join(O, 'modules', name), 'w', encoding='utf-8').write(ann)

    # 4) manifest + strings + iocs
    cols = ['out', 'sha256', 'size', 'kind', 'arch', 'bits', 'filetype',
            'type', 'usize', 'declen', 'source', 'offset']
    with open(os.path.join(O, 'manifest.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, '') for k in cols})
    json.dump(records, open(os.path.join(O, 'manifest.json'), 'w'), indent=2)
    with open(os.path.join(O, 'strings.txt'), 'w') as fh:
        fh.write('\n'.join(sorted(all_strings)))
    with open(os.path.join(O, 'iocs.txt'), 'w') as fh:
        fh.write('\n'.join(s for s in sorted(all_strings)
                           if _IOC.search(s) and 2 < len(s) < 200))

    n_macho = sum(1 for r in records if r['out'].startswith('macho/'))
    print(f"\n[=] {n_macho} Mach-O / {sum(1 for r in records if r['out'].startswith('native/'))} native "
          f"/ {sum(1 for r in records if r['out'].startswith('nextstage_js/'))} next-stage JS "
          f"/ {sum(1 for r in records if r['out'].startswith('payloads_enc'))} encrypted payloads")
    print(f"[=] {len(all_strings)} recovered strings -> strings.txt / iocs.txt")

    # 5) automatic decryption/unpack (handles everything with no arguments)
    #    (a) HTML master key -> 7a7d99 manifest -> 19 per-file keys (fully static, no device needed)
    #    (b) EMBEDDED_KEYS (variants outside the manifest + the master key)
    enc_sub = os.path.join(O, 'payloads_encrypted')
    if os.path.isdir(enc_sub):
        recs_map = {os.path.basename(r['out']): r.get('source', '').replace('.js', '')
                    for r in records if r['out'].startswith('payloads_enc')}
        static_keys = manifest_keys_from_capture(
            [t for _, t in raw_files], enc_sub, recs_map)
        if static_keys:
            print(f"\n[*] static derivation: HTML master key -> {len(static_keys)} per-file keys "
                  f"from the 7a7d99 manifest (no device needed)")
        keyset = {bytes.fromhex(v) for v in EMBEDDED_KEYS.values()}
        keyset |= set(static_keys.values())
        print(f"[*] auto-decrypting with {len(keyset)} total keys ...")
        decrypt_with_keylist(enc_sub, O, list(keyset))
        #    (c) second stage: each decrypted bundle's nested 0x12345678 config carries the
        #        keys of the second-level modules it chains to -- harvest and repeat until
        #        nothing new turns up (this is what takes the run from 24/30 to 30/30).
        for rnd in range(1, 5):
            more = {k: v for k, v in child_keys_from_decrypted(O).items()
                    if v not in keyset}
            if not more:
                break
            keyset |= set(more.values())
            resolved = {f[:-4] for f in os.listdir(os.path.join(O, 'decrypted_raw'))
                        if f.endswith('.bin')}
            print(f"\n[*] stage 2 round {rnd}: harvested {len(more)} second-level key(s) from "
                  f"nested 0x12345678 configs")
            decrypt_with_keylist(enc_sub, O, list(more.values()), known=resolved)

    print(f"\n[=] output directory: {O}/  (manifest.csv/json)")


if __name__ == '__main__':
    main()
