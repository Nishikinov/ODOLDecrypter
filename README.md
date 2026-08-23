# ODOLDecrypter

Standalone decryptor for encrypted **Arma 3 ODOL v75** models — the asset
protection Bohemia Interactive introduced for Creators DLC content
(*Reaction Forces* and newer), where binarized `.p3d` models ship with
non-zero encryption fields inside their header.

The tool restores regular, unencrypted ODOL v75 models that can be read by
standard modding tools.

## Features

- Batch processing: files, wildcards (`*.p3d`), directories, `-r` recursion,
  parallel execution across all CPU cores
- Both known ODOL v75 tweak variants:
  - simple size-derived tweak (`enc1` bit 1 clear) — e.g. *Reaction Forces*
  - FNV-1a name-hash tweak (`enc1` bit 1 set) — model-name candidates are
    derived from the input path automatically and validated
- Output is a valid plaintext ODOL v75 (enc fields zeroed), so re-running the
  tool is safe and idempotent
- Reports each model's Steam AppID and p3d prefix after decryption

## Usage

```
ODOLDecrypt <inputs...> [-o <outdir>] [-r] [-c] [--overwrite] [--inplace]

<inputs...>       .p3d files, wildcards (*.p3d) or directories
-o, --out <dir>   write decrypted files into <dir>
-r, --recursive   recurse into directories
-f, --overwrite   overwrite existing outputs
    --inplace     replace input files with their decrypted versions
-c, --copy-plain  also copy already-plaintext models into <dir>
```

Examples:

```
ODOLDecrypt.exe D:\models\*.p3d -o D:\models\decrypted
ODOLDecrypt.exe "D:\SteamLibrary\steamapps\common\Arma 3\@RF" -r -o out
```

> Note: not every Creators DLC encrypts its models — e.g. *Global Mobilization*
> ships regular plaintext ODOL v75 (`enc` fields are zero). Such files are
> skipped by default; pass `-c/--copy-plain` together with `-o` when batching a
> mixed directory and you want the complete set in the output folder.

## Building

Requires the .NET SDK 10 or newer ([download](https://dotnet.microsoft.com/download)) — no Visual Studio or other dependencies.

```
git clone https://github.com/Nishikinov/ODOLDecrypter.git
cd ODOLDecrypter
dotnet publish -c Release -r win-x64
```

The finished standalone executable appears in
`bin\Release\net10.0\win-x64\publish\ODOLDecrypt.exe` (~11 MB). It is fully
self-contained (trimmed and compressed): copy it anywhere and run on any
Windows x64 machine — no .NET installation required.

For a quick test without publishing you can run directly from source:

```
dotnet run -c Release -- <inputs...> [-o <dir>]
```

## How it works

The ODOL v75 header stays plaintext:

```
+0   "ODOL"
+4   version u32 (= 75)
+8   enc1 u32     \
+12  enc2 u32     / non-zero => payload from offset 16 is encrypted
```

Encryption is a per-4096-byte-block RC4 whose key material is never stored —
it is derived at load time from constants baked into `arma3_x64.exe`
(two key tables, a tolower table and a delimiter alphabet) plus per-file
values (the `enc` fields and the stream size):

| step | detail |
|------|--------|
| key16 | seed walk `0x25, +7 if x%3!=0 else +1, &0x7F` XOR table A/B (@`0x141B731E8` / `0x141B73200`), selected by bit 2 of enc1 |
| tweak | simple (bit1 clear): `b = size & 0xFF; s = b>>3 & 7; l = (-b) & 7; ((size >>> s) \| (size <<< l)) ^ size` |
| tweak | name-hashed (bit1 set): `A ^ B ^ size ^ fnv_low32`, where `B` is the size rotation above and `A = low32(rot64(fnv64))`; `fnv64` = FNV-1a-64 over the lowercased model-name suffix (part after the last `\` or `/`) |
| block key | `key16 XOR repeat_le32(~tweak ^ blockPos)` |
| KSA | standard RC4 KSA over an identity S-box |
| drop | LCG `x = x*0xC1C64E6D + 0x3039 (mod 2^31)` seeded with `blockPos ^ tweak`; a float-trick scales the draw into [256..512] PRGA pre-steps |
| PRGA | after the drop the index roles i/j are swapped, then the block is XORed |

The first 16 stream bytes are always plaintext.

## Limitations

- Windows x64 only (as the game itself).
- The name-hash variant depends on the model name the engine holds at load
  time; the tool probes candidates derived from the input path and validates
  each result. If none matches, add the expected string to
  `CandidateNames()` in `Program.cs`.
- Alternate key-table mode (`enc1` bit 2) is implemented per disassembly but
  was not exercised against real files.

## Disclaimer

This project is intended for **interoperability and research** (modding,
preservation, cryptography study). Use it only on content you legitimately
own or have permission to modify. Respect Bohemia Interactive's content
licensing terms; no original game data is included in this repository.

## License

[MIT](LICENSE)
