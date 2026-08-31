# Third-party notices

This file is included in packaged AccordLock Desktop applications by
`ui/desktop/forge.config.ts`. Paths and hashes below identify the exact source
files in this component. Package lockfiles remain authoritative for ordinary
Rust and JavaScript dependencies.

## Goose

AccordLock Desktop is a modified distribution derived from
[Goose](https://github.com/aaif-goose/goose). Goose is developed by its
upstream contributors and is licensed under the Apache License 2.0.
AccordLock-specific changes are not authored, endorsed, or certified by the
upstream Goose project.

- License: `LICENSE` (included beside this notice in packaged applications)
- Upstream source: <https://github.com/aaif-goose/goose>

## Embedded visualization libraries

The following browser distributions are compiled into the Auto Visualiser HTML
resources under `crates/goose-mcp/src/autovisualiser/templates/assets/`.
Version claims were checked against the named npm release archives and the
local files' SHA-256 digests.

| Local file | Exact upstream artifact | Relationship to upstream | Local SHA-256 | License |
| --- | --- | --- | --- | --- |
| `chart.min.js` | [`chart.js@4.5.0/dist/chart.umd.min.js`](https://registry.npmjs.org/chart.js/-/chart.js-4.5.0.tgz) | Byte-for-byte identical | `2f27bcf471b2d69dd78494f6e2172fb28470eb843820e2f96bb85d39f9618d30` | MIT |
| `d3.min.js` | [`d3@7.9.0/dist/d3.min.js`](https://registry.npmjs.org/d3/-/d3-7.9.0.tgz) | Identical except for four leading spaces added to each of its two lines | `d80e5b9417c6cf10eb68a143bf81c8cd505bb00eec8a8a8c1747db8612b27e13` | ISC |
| `d3.sankey.min.js` | [`d3-sankey@0.12.3/dist/d3-sankey.min.js`](https://registry.npmjs.org/d3-sankey/-/d3-sankey-0.12.3.tgz) | Identical except for four leading spaces added to each of its two lines | `0370152e5c56a8687a23f7f129ccc6d3eaaace998d8126add13b30e6e5af091c` | BSD-3-Clause |
| `leaflet.min.js` | [`leaflet@1.9.4/dist/leaflet.js`](https://registry.npmjs.org/leaflet/-/leaflet-1.9.4.tgz) | Byte-for-byte identical | `db49d009c841f5ca34a888c96511ae936fd9f5533e90d8b2c4d57596f4e5641a` | BSD-2-Clause |
| `leaflet.min.css` | [`leaflet@1.9.4/dist/leaflet.css`](https://registry.npmjs.org/leaflet/-/leaflet-1.9.4.tgz) | Text-identical; line endings normalized from CRLF to LF | `337bfca5cabd03b39815b2700febe2b3b7edf55921c59cd49f88ecb328212303` | BSD-2-Clause |
| `leaflet.markercluster.min.js` | [`leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js`](https://registry.npmjs.org/leaflet.markercluster/-/leaflet.markercluster-1.5.3.tgz) | Byte-for-byte identical | `1e4e1d22972a3926f48598e0caf14e3fe7049835d428a344fed4f9e3665b3508` | MIT |
| `mermaid.min.js` | [`mermaid@10.9.0/dist/mermaid.min.js`](https://registry.npmjs.org/mermaid/-/mermaid-10.9.0.tgz) | Byte-for-byte identical | `b2dbaa72ed85ae36025c33b2b56140e52a1413faf79e4a7a813825ccd4a56af5` | MIT |

### D3 7.9.0 — ISC

Copyright 2010-2023 Mike Bostock

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

### D3 Sankey 0.12.3 — BSD-3-Clause

Copyright 2015, Mike Bostock
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the author nor the names of contributors may be used to
  endorse or promote products derived from this software without specific prior
  written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Leaflet 1.9.4 — BSD-2-Clause

Copyright (c) 2010-2023, Volodymyr Agafonkin
Copyright (c) 2010-2011, CloudMade
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Leaflet.markercluster 1.5.3 — MIT

Copyright 2012 David Leaver

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Mermaid 10.9.0 — MIT

The MIT License (MIT)

Copyright (c) 2014 - 2022 Knut Sveidqvist

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

### Chart.js 4.5.0 — MIT

The MIT License (MIT)

Copyright (c) 2014-2024 Chart.js Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Local Whisper transcription

`crates/goose/src/dictation/whisper.rs` contains substantially modified,
adapted portions of the
[Hugging Face Candle 0.11.0 Whisper example](https://github.com/huggingface/candle/blob/0.11.0/candle-examples/examples/whisper/main.rs).
Candle offers its work under Apache-2.0 OR MIT; this distribution selects
Apache-2.0 for those portions. The complete Apache License 2.0 is in `LICENSE`,
which is packaged beside this notice.

The two embedded mel-filter tables are byte-for-byte copies of Candle 0.11.0
assets. The embedded multilingual tokenizer is a byte-for-byte copy of
[`openai/whisper-tiny` at snapshot `169d4a4341b33bc18d8881c4b69c2e104e1cc0af`](https://huggingface.co/openai/whisper-tiny/blob/169d4a4341b33bc18d8881c4b69c2e104e1cc0af/tokenizer.json),
whose model card declares Apache-2.0. Exact file hashes are recorded in
`crates/goose/src/dictation/whisper_data/README.md`.

OpenAI's Whisper project states that its code and model weights are released
under the following MIT license. This notice is retained for the underlying
Whisper work represented by the tokenizer and decoding implementation.

### OpenAI Whisper — MIT

MIT License

Copyright (c) 2022 OpenAI

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

The GGUF model files named in `whisper.rs` are downloaded on demand. They are
not committed to this repository or included in desktop installers. Their
model-card terms apply independently.
