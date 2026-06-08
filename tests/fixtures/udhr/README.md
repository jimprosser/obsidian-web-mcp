# Multilingual test fixtures (UDHR excerpts)

These files are short excerpts from the Universal Declaration of Human Rights
(UDHR), used as authentic, real-world multilingual text for the
serialization/encoding tests (verbatim non-ASCII output, round-trip integrity,
and response size at scale).

## Source and license

The UDHR is treated as **freely reproducible**: the United Nations encourages its
free reproduction and translation. Plain-text UTF-8 translations are distributed
by the Unicode UDHR project and the NLTK `udhr2` corpus. The files here are
bounded excerpts (roughly the opening of the preamble, under about 1000
characters per language) taken from that text. No attribution is required; the
source is recorded here only for provenance.

## Files

One excerpt per script, each UTF-8 and newline-terminated:

| File | Script |
|------|--------|
| `korean.txt` | Korean (Hangul) |
| `japanese.txt` | Japanese (Kana + Kanji) |
| `chinese.txt` | Chinese (Simplified Han) |
| `russian.txt` | Russian (Cyrillic) |
| `arabic.txt` | Arabic (RTL) |
| `hindi.txt` | Hindi (Devanagari) |
| `greek.txt` | Greek |
| `hebrew.txt` | Hebrew (RTL) |
| `thai.txt` | Thai |
| `french.txt` | French (Latin with diacritics) |
