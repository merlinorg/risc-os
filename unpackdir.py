#!/usr/bin/env python3
# Copyright (C) 2026 Merlin Hughes
# SPDX-License-Identifier: GPL-3.0-or-later
"""Extract RISC OS PackDir (,68e) archives.

Container:  "PACK" | byte 0 | word maxbits-code | root: name\0 load exec count attr
Entries:    name\0 load exec length attr type [complen]   type 1 = dir (length = entry count)
            complen 0xFFFFFFFF = stored; otherwise LZW (LSB-first, clear 256, first free 258)
Files are written with RISC OS ,xxx filetype suffixes, as in the extracted trees.
"""
import sys, os, struct, argparse

def lzw_decompress(data, maxbits):
    out = bytearray()
    dic = {i: bytes([i]) for i in range(256)}
    nxt, width, prev = 258, 9, None
    bitpos, total = 0, len(data) * 8
    while bitpos + width <= total:
        byi, sh = bitpos >> 3, bitpos & 7
        code = (int.from_bytes(data[byi:byi+4].ljust(4, b'\0'), 'little') >> sh) & ((1 << width) - 1)
        bitpos += width
        if code == 256:
            dic = {i: bytes([i]) for i in range(256)}
            nxt, width, prev = 258, 9, None
            continue
        if code == 257:
            break
        if code in dic:
            entry = dic[code]
        elif code == nxt and prev is not None:
            entry = prev + prev[:1]
        else:
            break
        out += entry
        if prev is not None:
            dic[nxt] = prev + entry[:1]
            nxt += 1
        prev = entry
        if nxt >= (1 << width) and width < maxbits:
            width += 1
    return bytes(out)

RISCOS_EPOCH = 2208988800  # seconds from 1900-01-01 to 1970-01-01

def riscos_mtime(load, exec_):
    """RISC OS datestamp: 5-byte centisecond count since 1900, split across load/exec."""
    if (load >> 20) != 0xFFF:
        return None
    return ((load & 0xFF) << 32 | exec_) / 100.0 - RISCOS_EPOCH

def suffix(load):
    if (load >> 20) == 0xFFF:
        return ",%03x" % ((load >> 8) & 0xFFF)
    return ""

class Reader:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        assert self.d[:4] == b'PACK', "not a PackDir archive"
        self.maxbits = {0: 12, 1: 13, 2: 14, 3: 15, 4: 16}.get(
            struct.unpack_from('<I', self.d, 5)[0], 16)
        self.files = self.dirs = self.bad = 0

    def name(self, p):
        e = self.d.index(b'\0', p)
        return self.d[p:e].decode('latin-1'), e + 1

    def run(self, outdir, verbose):
        root, p = self.name(9)
        load, ex, count, attr = struct.unpack_from('<4I', self.d, p)
        print(f"archive root: {root}  ({count} entries, maxbits={self.maxbits})")
        self.walk(p + 16, count, outdir, verbose)
        print(f"{self.dirs} dirs, {self.files} files, {self.bad} length mismatches")
        return self.bad

    def walk(self, p, count, outdir, verbose):
        for _ in range(count):
            nm, p = self.name(p)
            load, ex, length, attr, typ = struct.unpack_from('<5I', self.d, p)
            p += 20
            safe = nm.replace('/', '.')
            if typ == 1:
                sub = os.path.join(outdir, safe)
                os.makedirs(sub, exist_ok=True)
                self.dirs += 1
                p = self.walk(p, length, sub, verbose)
            else:
                clen, = struct.unpack_from('<I', self.d, p)
                p += 4
                if clen == 0xFFFFFFFF:
                    body, clen = self.d[p:p+length], length
                else:
                    body = lzw_decompress(self.d[p:p+clen], self.maxbits)
                p += clen
                if len(body) != length:
                    self.bad += 1
                    print(f"  !! {os.path.join(outdir, safe)}: got {len(body)}, expected {length}")
                dest = os.path.join(outdir, safe + suffix(load))
                with open(dest, 'wb') as f:
                    f.write(body)
                mt = riscos_mtime(load, ex)
                if mt is not None and 0 < mt < 4e9:
                    os.utime(dest, (mt, mt))
                self.files += 1
                if verbose:
                    print(f"  {dest}  {length}")
        return p

def self_test():
    """Checked against real bytes from a 1993 archive, not against our own
    encoder -- a decoder tested with a matching encoder only proves the two
    agree with each other."""
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append("%s: got %r want %r" % (name, got, want))

    # The "!Boot" member of Miskatonic/String/tetris,68e: 58 compressed bytes
    # whose plaintext survives unpacked elsewhere in that archive.
    blob = (b'\x00\xa7\x94\xa1\x03\x82J\x199t\xd2\xcc!A$\x8d\x1c\x10<\x9e\x88)'
            b'\x93\x87\xa1C\x1f.\x14$\x19\xf3\xc6\xcd\x148r\xd2\xd0)3\x07\xa2A'
            b'\x84\n-\xca\xf1\x11\xe2c\xc8\x91s\x14\x04\x04')
    want = b"Set Tertis$Dir <Obey$Dir>.\nIconSprites <Tertis$Dir>!Sprites\n"
    check("lzw !Boot", lzw_decompress(blob, 12), want)
    check("lzw length", len(lzw_decompress(blob, 12)), 60)

    # Its datestamp, and its filetype suffix.
    check("mtime", round(riscos_mtime(0xFFFFEB44, 0x901CE2FB)), 735767083)
    check("suffix feb", suffix(0xFFFFEB44), ",feb")
    check("suffix none", suffix(0x00008000), "")

    # A hand-built archive: one stored file (complen -1) inside one directory.
    body = (b"d\0" + struct.pack('<5I', 0xFFFFFD00, 0, 1, 0, 1)
            + b"f\0" + struct.pack('<5I', 0xFFFFFD00, 0, 3, 0, 0)
            + struct.pack('<I', 0xFFFFFFFF) + b"abc")
    arc = (b"PACK\0" + struct.pack('<I', 0) + b"root\0"
           + struct.pack('<4I', 0xFFFFFD00, 0, 1, 0) + body)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "a.68e")
        open(src, 'wb').write(arc)
        out = os.path.join(td, "out")
        os.makedirs(out)
        bad = Reader(src).run(out, False)
        check("stored member", bad, 0)
        check("stored bytes", open(os.path.join(out, "d", "f,ffd"), 'rb').read(),
              b"abc")

    if fails:
        print("SELF-TEST FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("self-test OK")
    return 0


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('archive', nargs='?', help='the .68e / PackDir archive')
    ap.add_argument('outdir', nargs='?', help='directory to extract into')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        sys.exit(self_test())
    if not a.archive or not a.outdir:
        ap.error("need an archive and an output directory")
    os.makedirs(a.outdir, exist_ok=True)
    sys.exit(1 if Reader(a.archive).run(a.outdir, a.verbose) else 0)
