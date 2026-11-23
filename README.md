<p align="center">
  <img src="docs/banner.svg" alt="promptshield" width="100%">
</p>

**Catch prompt injection and hidden text _before_ it reaches your LLM.**

[![CI](https://github.com/tahaSec/promptshield/actions/workflows/ci.yml/badge.svg)](https://github.com/tahaSec/promptshield/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

RAG pipelines, browsing agents and "summarize this PDF" features all feed
untrusted text into a model. Attackers hide instructions in that text: in
invisible Unicode, in white-on-white CSS, in HTML comments, in base64 blobs.
A human reviewer sees a normal page. The model sees *"ignore previous
instructions"*.

`promptshield` is a small, dependency-free scanner that finds these tricks
and **shows you the hidden text**.

<p align="center">
  <img src="docs/demo.svg" alt="promptshield demo output" width="100%">
</p>

## Features

- **ASCII smuggling decoder**: finds Unicode tag characters (U+E0000 to U+E007F) and prints the hidden message.
- **Zero-width characters**, including hidden binary messages encoded with ZWSP/ZWNJ (decoded automatically).
- **Trojan Source** bidirectional overrides (U+202E and related).
- **Homoglyph words** that mix Latin with Cyrillic or Greek, like `pаypal`.
- **Injection phrases** in English and Turkish: instruction overrides, persona hijacks, system prompt extraction, "don't tell the user".
- **Fake chat-template tokens** such as `<|im_start|>system`, `[INST]` and `<<SYS>>`.
- **Exfiltration** through markdown images like `![](https://evil/?data=...)` and "send this to https://..." instructions.
- **Hidden HTML**, meaning `display:none`, `font-size:0`, white text, off-screen text, and comments addressed to AI.
- **Base64 payloads** that decode to injections.
- **`--sanitize`** strips invisible and control characters while leaving visible text unchanged.
- Risk score (0-100), JSON output and CI-friendly exit codes.
- **Zero dependencies.** Pure Python 3.9+ on Linux, macOS and Windows.

## Install

```bash
pip install git+https://github.com/tahaSec/promptshield
```

Or clone it and run `pip install -e .`

## Usage

```bash
promptshield document.txt                 # scan a file
promptshield docs/ --ext md --ext html    # scan a folder
curl -s https://example.com | promptshield -          # scan a web page
promptshield page.html -f json            # machine-readable output
promptshield input.txt --sanitize > clean.txt          # strip hidden characters
promptshield data/ --fail-on critical     # only fail CI on critical findings
```

Exit code: `0` means clean. `1` means a finding at or above `--fail-on` was found (default `high`).

### In Python (RAG / agent pipelines)

```python
from promptshield import scan, sanitize

def safe_context(chunk: str) -> str:
    report = scan(chunk, source="retrieved-doc")
    if report.max_severity in ("high", "critical"):
        raise ValueError(f"Blocked chunk, risk {report.risk_score}: "
                         f"{[f.rule_id for f in report.findings]}")
    return sanitize(chunk)
```

### In GitHub Actions

Fail a pull request if someone adds poisoned content to your prompts or knowledge base:

```yaml
- run: pip install git+https://github.com/tahaSec/promptshield
- run: promptshield prompts/ knowledge_base/ --fail-on high
```

## Rules

| ID | Severity | Detects |
|----|----------|---------|
| PS001 | critical/high | Unicode tag characters (ASCII smuggling), decoded |
| PS002 | low to high | Zero-width characters, binary payloads decoded |
| PS003 | high | Bidi control characters (Trojan Source) |
| PS004 | high | Variation selector data hiding |
| PS005 | medium | Mixed-script homoglyph words |
| PS100 / PS101 | high | "Ignore previous instructions" (EN / TR) |
| PS102 | medium | Persona hijack ("you are now ...") |
| PS103 | high | Fake chat template / role tokens |
| PS104 | high | System prompt / secret extraction |
| PS105 | medium | "Do not tell the user" |
| PS106 | high | Markdown image exfiltration |
| PS107 | medium | "Send ... to https://..." |
| PS108 | medium | Tool / shell action injection |
| PS109 | low | Text addressed to an AI model |
| PS110 | medium | Jailbreak keywords |
| PS200 | critical/medium | CSS-hidden HTML text |
| PS201 | high | HTML comments with AI instructions |
| PS300 | critical | Base64 payload containing an injection |

## Limitations

This is a **heuristic, defence-in-depth** filter, not a guarantee. A
determined attacker can paraphrase around phrase rules. Use it together with
least-privilege tools, output filtering and human confirmation for sensitive
actions. The character-level checks (smuggling, zero-width, bidi) have very
low false positive rates. The phrase checks are tuned to be quiet on normal
prose and code.

## Contributing

New bypasses and false positives are very welcome. Please open an issue with
a sample. Run the tests with:

```bash
pip install -e ".[dev]" && pytest
```

---

## Türkçe

`promptshield`, LLM'e gönderilen metinlerde (RAG belgeleri, web sayfaları,
PDF'ten çıkan yazılar) gizlenmiş **prompt injection** saldırılarını bulan,
bağımlılığı olmayan bir tarayıcıdır. Görünmez Unicode karakterlerle (ASCII
smuggling), CSS ile gizlenmiş yazılarla, HTML yorumlarıyla veya base64 ile
saklanmış talimatları yakalar ve **gizli metni açığa çıkarır**. Türkçe
saldırı kalıplarını da tanır ("önceki talimatları yok say" gibi).

```bash
pip install git+https://github.com/tahaSec/promptshield
promptshield belge.txt
```

## License

MIT © Muhammed Taha Özer
