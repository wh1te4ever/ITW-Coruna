# ITW-Coruna
Captures of ITW-Coruna

### extract.py run result
```
seo@seos-MacBook-Air Coruna-20260710 % ./extract.py -o extracted .
[*] 81 inputs / 90 flattened layers
[+] macho                arm64        DYLIB        89328B  embedded@0xd60
[+] macho                arm64+arm64e FAT         183600B  embedded@0x1d0
[+] macho                arm64        DYLIB        85576B  embedded@0x41d0
[+] macho                arm64e       DYLIB        68912B  embedded@0x1c1d0
[+] native               arm64        TEXT_container    208432B  @0x0
[+] nextstage_js         x            nextstage    374123B  @0x0
[+] nextstage_js         x            nextstage    323631B  @0x0
[+] payloads_encrypted   x            qbrdr_enc    137024B  5258f6e3eef3eda249179a@0x0
[+] payloads_encrypted   x            qbrdr_enc    232584B  81b403cc1fe0c47839c4ad@0x0
[+] payloads_encrypted   x            qbrdr_enc    174992B  7a1cef00016b950be42f52@0x0
[+] payloads_encrypted   x            qbrdr_enc    228340B  1ad1ff474e417d0a07ff1e@0x0
[+] payloads_encrypted   x            qbrdr_enc    168596B  f4120dc6717a489435d869@0x0
[+] payloads_encrypted   x            qbrdr_enc    158672B  e9f898587620186e31119f@0x0
[+] payloads_encrypted   x            qbrdr_enc    228340B  667fa543143862135ab6b4@0x0
[+] payloads_encrypted   x            qbrdr_enc     26360B  5e89f83ec50c6223d664d3@0x0
[+] payloads_encrypted   x            qbrdr_enc    141864B  b442ab113b829ff8c7bf34@0x0
[+] payloads_encrypted   x            qbrdr_enc    232584B  3215fc5c0f7e2ccced7105@0x0
[+] payloads_encrypted   x            qbrdr_enc    197776B  1334417664270db20af705@0x0
[+] payloads_encrypted   x            qbrdr_enc    173140B  1b2cbbde08f8b2330b7400@0x0
[+] payloads_encrypted   x            qbrdr_enc    228312B  4612aa650e60e2974a9ec3@0x0
[+] payloads_encrypted   x            qbrdr_enc     26568B  2a1d692b7b5ba793527b2c@0x0
[+] payloads_encrypted   x            qbrdr_enc      1320B  7a7d99099b035b2c6512b6@0x0
[+] payloads_encrypted   x            qbrdr_enc    224484B  377bed7460f7538f96bbad@0x0
[+] payloads_encrypted   x            qbrdr_enc    232584B  e3b865be8672d1357bdaac@0x0
[+] payloads_encrypted   x            qbrdr_enc    161052B  226cbd845c5f4700755053@0x0
[+] payloads_encrypted   x            qbrdr_enc    152784B  72a5ac816709f9c331f2b3@0x0
[+] payloads_encrypted   x            qbrdr_enc    171300B  ae7efd66ecde9e964cfe92@0x0
[+] payloads_encrypted   x            qbrdr_enc    232584B  a159973efdd00dd988fec1@0x0
[+] payloads_encrypted   x            qbrdr_enc    228340B  fb95e427382180860f0b48@0x0
[+] payloads_encrypted   x            qbrdr_enc    157016B  38af3c8ba461079a0edc83@0x0
[+] payloads_encrypted   x            qbrdr_enc    153356B  980c77f1747afa9ac1fa5f@0x0
[+] payloads_encrypted   x            qbrdr_enc    232584B  4817ea8063eb4480e915f1@0x0
[+] payloads_encrypted   x            qbrdr_enc    133268B  4800048658463f971e752f@0x0
[+] payloads_encrypted   x            qbrdr_enc    152292B  f8a86cf368fdbbe2948139@0x0
[+] payloads_encrypted   x            qbrdr_enc    146876B  a78a94196b5d2c95865f6a@0x0
[+] payloads_encrypted   x            qbrdr_enc    228340B  800d80e0fa1f2baf9a9e41@0x0
[+] payloads_encrypted   x            qbrdr_enc    168596B  c8a14d79a27953242d6024@0x0

[=] 4 Mach-O / 1 native / 2 next-stage JS / 30 encrypted payloads
[=] 228 recovered strings -> strings.txt / iocs.txt

[*] static derivation: HTML master key -> 19 per-file keys from the 7a7d99 manifest (no device needed)
[*] auto-decrypting with 24 total keys ...
  [OK] 00ecf604944545b4 key=7ae216d3b4ba8b41... -> macho x1
  [OK] 538699f9277fbcbb key=e6542d26109c5c3a... -> macho x3
  [OK] a663ef8752c2eb9e key=58199343c3811b01... -> macho x4
  [OK] 95797c4e86e88b74 key=176f3b0d80c6c94f... -> macho x3
  [OK] a4cba5201a0f3bf2 key=b252669de4b4adc3... -> macho x1
  [OK] c46f10963abb667a key=b38fd1ccd6570d8b... -> macho x1
  [OK] 88b8e089f03c4609 key=6c682a65deb7cf02... -> macho x3
  [OK] 91626dd665310733 key=a19b901b47f9dd7b... -> macho x2
  [OK] 13a9a53e1ec42abc key=3cb781d9c1ade5c3... -> macho x4
  [OK] 3ee07d1b434ab2d7 key=bdff99612a2aa99a... -> macho x4
  [OK] 967c577574923c0a key=a6244c09c0588cf1... -> macho x4
  [OK] bf653c4bc2ee0a95 key=230ddaa380a7899e... -> macho x3
  [OK] d2bf9142d7bb5b2d key=7da5f7d73e652aa7... -> macho x1
  [OK] 9bf78735bcea0455 key=50a323f335f2bf46... -> macho x3
  [OK] a3252b27c1bce121 key=338bf220589af21d... -> macho x1
  [OK] f1516320e053d109 key=04da244132e7096d... -> macho x1
  [OK] 8f37fc4700c89510 key=85ab5908ceb1981d... -> macho x1
  [OK] 571cc54da99889e4 key=be7efb67c5b39656... -> macho x2
  [OK] 6d1905d51649cc42 key=6662406a17f3a38f... -> macho x3
  [OK] 9ebfe2493e155623 key=8360789e772f5512... -> macho x3
  [OK] 269665b1fa282020 key=cab13d34917b6f5b... -> macho x4
  [OK] 6bf4caa49c840f05 key=c02c657bb22d6cfc... -> macho x1
  [OK] e1ff1b24517654ec key=fdd8b3940d2a06b0... -> macho x3
  [OK] 1c52cc500ab818af key=388976a2cdce9664... -> macho x4
[=] decrypted 24/30 blobs - 60 Mach-O -> extracted/decrypted/
[!] 6 unresolved: need to collect more keys. e.g. 0d42ae58baf10097 ...

[*] stage 2 round 1: harvested 6 second-level key(s) from nested 0x12345678 configs
  [OK] a0d313c0b3d6684a key=a1cfc122350d103d... -> macho x1
  [OK] cb0b19264414e1bf key=30041769ac1061ea... -> macho x1
  [OK] 1bda4348cfce300f key=7fb9b6821d97f710... -> macho x1
  [OK] b15eaa9245efae6d key=feeb9b36649003a6... -> macho x1
  [OK] c4e0a45c0f5a68f4 key=9622b5532c3308ad... -> macho x1
  [OK] 0d42ae58baf10097 key=00afe7b09f138818... -> macho x1
[=] decrypted 30/30 blobs - 6 new Mach-O -> extracted/decrypted/

[=] output directory: extracted/  (manifest.csv/json)
```

All 30 blobs now decrypt with no device and no runtime key dump. The last 6 are the
second-level modules, and their ChaCha20 keys are not in the `7a7d99` manifest — each one sits in
the *nested* `0x12345678` config that its parent bundle carries as its last `type 0x07` entry
(468 B = `0x10c` header + 2 × `0x64`), same layout as the manifest: `+0x00` u32 id, `+0x04` 32-byte
key, `+0x24` name. `child_keys_from_decrypted()` harvests them after the first pass and repeats
until nothing new appears, which is what takes the run from 24/30 to 30/30.

The 10 second-level modules de-duplicate to **3 distinct binaries**, all
`/usr/local/lib/SamplePayload.dylib` (referencing `powerd.bundle/powerd` and `/tmp/upgrade.dylib`):

| sha256 | size | arch | served as |
|---|---|---|---|
| `e258c0b70ed7b4be…` | 715 760 | arm64 | `0x02300000`, `0x02400000`, `0x02700000`, `0x02800000` |
| `63ffff883f78ecca…` | 715 760 | arm64 | `0x02900000` only |
| `59592bc95876eaf3…` | 747 936 | arm64e (PAC) | all five `0xe2…` IDs |

### iOS targeting

`extracted/manifest.csv` / `.json` carry 11 extra columns saying which iOS versions each artifact is
used on, decoded from the selector in `payloads/bootstrap.dylib`. See
[extracted/manifest_targeting.md](extracted/manifest_targeting.md); regenerate with
`python3 annotate_targeting.py --write`.
