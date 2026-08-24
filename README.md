# riscos

Three standalone Python 3 tools for reading data off 1990s Acorn RISC OS discs.
No dependencies. Each has a `--self-test`.

They were written to recover a 1997 archive of an Acorn Archimedes machine, and
are validated against it — roughly 22,000 files across four SCSI discs and a box
of floppies.

## `debasic.py` — tokenised BBC BASIC V (`,ffb`) → text

```
debasic.py FILE...                  # faithful, with line numbers
debasic.py -n -p FILE...            # no line numbers, readable spacing
debasic.py -o OUTDIR FILE...        # mirror a tree
```

Handles two-byte tokens, the `&8D` inline line-number references behind
`GOTO`/`GOSUB`/`RESTORE`, and inline ARM assembler — where `ORR`/`ANDS`/`EORS`
are stored as an `OR`/`AND`/`EOR` token glued to the rest of the mnemonic, and
must not be split.

`-p` is a reading copy, not a rewrite: it only ever *inserts* spaces, so
stripping them back gives the canonical text exactly. Verified over 442,693
lines.

## `unpackdir.py` — PackDir (`,68e`) archives

```
unpackdir.py ARCHIVE OUTDIR
```

LZW inside a simple container. Restores RISC OS filetype suffixes and
datestamps. Verified against files that also survive unpacked: byte-identical,
dates included.

Archives split across floppies as `,307` parts reassemble first — 28-byte
header, fragment offset at +24, concatenate in offset order.

## `adfsimg.py` — build an ADFS floppy image

```
adfsimg.py SRCDIR OUT.adf [--name DISCNAME]
```

Writes an 800K ADFS D-format `.adf` from a host directory in the `,xxx`
filetype convention, for mounting under [Arculator](https://b-em.bbcmicro.com/arculator/)
or [ArcEm](https://arcem.sourceforge.net/).

## Format notes

**PackDir.** `"PACK"`, a zero byte, a word selecting max LZW code width
(`0`→12 … `4`→16), then the root: name, load, exec, entry count, attributes.
Each entry is name, load, exec, length, attributes, type; type 1 is a directory
whose `length` is its entry count and whose children follow, type 0 is a file
followed by a compressed-length word and its data, where `0xFFFFFFFF` means
stored. LZW is LSB-first, variable width 9 → max, 256 clears, 257 ends, first
free code 258.

**`&8D` line numbers.** BASIC holds the top two bits of each half of the line
number in the first of three bytes and **XORs** them back out — it does not mask
them in. Getting this wrong yields plausible, wrong line numbers.

## Licence

GPL-3.0-or-later.
