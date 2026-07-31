# Third-party notices

The USB-HID framing, checksum, synchronization sequence, initialization
commands, and PN532 bridge behavior in this project are based on:

- Project: `wcopy-nfc-linux`
- Author: Mario Giordano
- Source: https://github.com/mariogiordano96/wcopy-nfc-linux
- License: MIT

The upstream license follows.

```text
MIT License

Copyright (c) 2026 Mario Giordano

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Optional runtime dictionaries

The application can optionally download and parse key dictionaries at runtime
from the following projects. These dictionary files are not bundled with or
copied into this project. Users who load them should refer to the source
project's license and notices.

- Proxmark3 `mfc_default_keys.dic`: https://github.com/RfidResearchGroup/proxmark3
- MIFARE Classic Tool `extended-std.keys`: https://github.com/ikarus23/MifareClassicTool

The compact built-in presets are independently curated from publicly known
MIFARE defaults, test patterns, and generated weak patterns. The common preset
includes the default values conventionally tried by mfoc.

## Native Crypto1 and nested-key recovery

The in-process Crypto1 cipher, PRNG distance measurement, LFSR state recovery,
and nested-authentication key recovery in `Crypto1.swift` and
`NestedRecovery.swift` are an original implementation of the published MIFARE
Classic Crypto1 algorithm and the mfoc nested-attack flow. They were written
independently (no GPL source is vendored or transliterated) and pinned to the
behavior of the reference `mfoc`/`crapto1` implementation by generated test
vectors in `Crypto1Tests.swift`.

- Reference behavior source (not redistributed):
  https://github.com/nfc-tools/mfoc (GPL-2.0)
- Protocol papers: *Dismantling MIFARE Classic* (Garcia et al., ESORICS 2008);
  *Wirelessly Pickpocketing a Mifare Classic Card* (Courtois, Nohl, O'Neil 2008)
