# Embedded Whisper data provenance

These files support the optional local dictation feature. They are source
inputs embedded in the Goose binary; model weights are downloaded separately
and are not stored here.

| File | SHA-256 | Exact source | License |
| --- | --- | --- | --- |
| `melfilters.bytes` | `85818f156f7e189453901a515e4726d270d307f976e161cf9403e8caab405498` | [Candle 0.11.0 Whisper example](https://github.com/huggingface/candle/blob/0.11.0/candle-examples/examples/whisper/melfilters.bytes) | Apache-2.0, selected from Candle's Apache-2.0 OR MIT terms |
| `melfilters128.bytes` | `2a5f9822897750e047c85dea37cc268d3be0ecfd23c28a5f10da129d99d05afe` | [Candle 0.11.0 Whisper example](https://github.com/huggingface/candle/blob/0.11.0/candle-examples/examples/whisper/melfilters128.bytes) | Apache-2.0, selected from Candle's Apache-2.0 OR MIT terms |
| `tokens.json` | `27fc476bfe7f17299480be2273fc0608e4d5a99aba2ab5dec5374b4482d1a566` | [`openai/whisper-tiny` snapshot `169d4a4341b33bc18d8881c4b69c2e104e1cc0af`](https://huggingface.co/openai/whisper-tiny/blob/169d4a4341b33bc18d8881c4b69c2e104e1cc0af/tokenizer.json) | Apache-2.0 according to the snapshot model card; the underlying OpenAI Whisper notice is also retained |

The Apache License 2.0 is in the desktop component's `LICENSE`. The complete
OpenAI Whisper MIT notice and a record of the Candle adaptation are in the
desktop component's `THIRD_PARTY_NOTICES.md`; both files are included in
packaged desktop applications.
