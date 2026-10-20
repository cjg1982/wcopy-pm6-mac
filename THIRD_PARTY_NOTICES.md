# Third-party notices

## Direct macOS upstream

This adaptation inherits the application from zhjcreator/wcopy-nfc-mac,
commit 9adcfbfdb3b3caafb26cc6f76aef32eb823302fd (MIT).
Copyright (c) 2026 wCopy NFC for Mac contributors.
The complete upstream MIT license is retained in LICENSE.
See docs/PROVENANCE.md for local changes, Windows binary references,
AI assistance and outstanding algorithm-source review.

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

The base Crypto1 and Nested recovery files are inherited from the macOS
upstream identified above and modified locally. Upstream describes them as an
independent implementation of the published algorithm, checked against
mfoc/crapto1 behavior. This adaptation has not independently established that
claim through a complete source-provenance audit. See docs/PROVENANCE.md.
Acknowledgment does not replace any license obligations for copied or
translated source; public redistribution requires resolving that provenance.

- Reference behavior source (not redistributed):
  https://github.com/nfc-tools/mfoc (GPL-2.0)
- Protocol papers: *Dismantling MIFARE Classic* (Garcia et al., ESORICS 2008);
  *Wirelessly Pickpocketing a Mifare Classic Card* (Courtois, Nohl, O'Neil 2008)
