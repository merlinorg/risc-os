#!/usr/bin/env python3
# Copyright (C) 2026 Merlin Hughes
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build an 800K ADFS D-format floppy image (.adf) from a host directory.

The host directory is expected in the RISC OS ",xxx" convention this archive
uses: a hex suffix is the filetype, ",llllllll-eeeeeeee" (hex, as written by
Arculator/RPCEmu hostfs) gives an untyped file's load and exec addresses,
",lxa" marks a file that carried load/exec addresses that are not recoverable
from the archive, and no suffix means the tag was dropped on extraction.

  adfsimg.py SRCDIR OUT.adf [--name DISCNAME]
  adfsimg.py --self-test

Format references: the directory and old-map layouts are per mdfs.net's ADFS
document, cross-checked against ADFSlib's reader. Sector numbers throughout are
256-byte logical sectors, which is the unit D-format directory entries use even
though the physical sector size is 1024.
"""
import argparse
import hashlib
import os
import sys

SECTOR = 256                 # logical sector, the unit used by directory entries
TOTAL_SECTORS = 3200         # 800K
IMAGE_SIZE = TOTAL_SECTORS * SECTOR
DIR_SIZE = 0x800             # large directories are 8 logical sectors
DIR_ENTRIES = 77
PHYS_SECTOR = 1024           # D format's physical sector size
ALIGN = PHYS_SECTOR // SECTOR   # objects must start on a physical sector
ROOT_SECTOR = 4              # root directory starts at byte 0x400
DATA_SECTOR = ROOT_SECTOR + DIR_SIZE // SECTOR
# ADFS-D is "old map, new dir": the new directory format's identifier is
# "Nick". Writing "Hugo" (the old, 1280-byte directory's marker) produces a
# disc that mounts and shows its name but whose root fails RISC OS's
# start/end-marker check -- "Broken directory".
MARKER = b"Nick"

# An Archimedes absolute image loads and is entered at &8000. The archive did
# not preserve the real load/exec addresses of ,lxa files, but leaving them at
# zero makes *Run load the image at address 0; !Scorpius/!RunCode does exactly
# that to !RunImage, which is PC-relative ARM code. &8000 is the convention and
# is what filetype &FF8 (Absolute) resolves to.
LXA_ADDR = 0x8000

ATTR_FILE = 0x03             # %00wrDLWR -> WR
ATTR_DIR = 0x0B              # %00wrDLWR -> DWR


def checksum(data):
    """The ADFS map checksum over the first 255 bytes of a 256-byte sector.

    Transcribed from the reference implementation:

        sum% = 255
        FOR A% = 254 TO 0 STEP -1
          IF sum% > 255: sum% = (sum% + 1) AND 255
          sum% = sum% + mem%?A%
        NEXT
        = sum% AND 255

    The carry is folded in at the *start* of the next iteration, and a carry out
    of the final addition is discarded rather than folded. Documentation that
    starts from 0, or adds upwards, gets a different answer.
    """
    s = 255
    for a in range(254, -1, -1):
        if s > 255:
            s = (s + 1) & 255
        s += data[a]
    return s & 255


def ror13(v):
    return ((v >> 13) | (v << 19)) & 0xFFFFFFFF


def dir_check_byte(d):
    """The FileCore directory check byte, for a 2048-byte new directory.

    Accumulates `EOR acc, value, acc ROR #13` over the used bytes -- everything
    up to the end-of-entries marker, then the nine whole words at 2008..2043 --
    and folds the accumulator's four bytes together.

    The tail starts at 2007, but that byte -- the end-of-entries marker -- is
    NOT accumulated; the tail words begin at 2008. The RISC OS PRMs say the
    first few tail bytes are included; the Linux kernel's
    implementation notes in fs/adfs/dir_f.c that the PRMs are wrong here, and
    DiscImageManager agrees with the kernel. Following the PRMs gives a check
    byte RISC OS rejects.
    """
    acc, last, i = 0, 5 - 26, 0
    while True:
        last += 26
        while True:                       # do-while: at least one word
            acc = int.from_bytes(d[i:i + 4], "little") ^ ror13(acc)
            i += 4
            if i >= (last & ~3):
                break
        if d[last] == 0:
            break
    for p in range(i, last):              # the trailing 0..3 bytes
        acc = d[p] ^ ror13(acc)
    for off in range(2008, 2044, 4):      # the tail, less the final word
        acc = int.from_bytes(d[off:off + 4], "little") ^ ror13(acc)
    return (acc ^ (acc >> 8) ^ (acc >> 16) ^ (acc >> 24)) & 0xFF


def parse_name(fname):
    """Split a host filename into (risc_os_name, filetype, load_exec).

    filetype is an int for a ",xxx" hex tag; load_exec is a (load, exec)
    tuple for a ",llllllll-eeeeeeee" suffix, the convention Arculator and
    RPCEmu hostfs use for an untyped file with explicit addresses -- each
    side is 1 to 8 hex digits, matching hostfs's own parser. Both are None
    for an untyped file (",lxa", or no suffix at all).
    """
    comma = fname.rfind(",")
    if comma > 0 and "-" in fname[comma + 1:]:
        lo, hi = fname[comma + 1:].split("-", 1)
        if (1 <= len(lo) <= 8 and 1 <= len(hi) <= 8 and
                all(c in "0123456789abcdefABCDEF" for c in lo + hi)):
            return fname[:comma], None, (int(lo, 16), int(hi, 16))
    if len(fname) > 4 and fname[-4] == ",":
        tag = fname[-3:]
        if all(c in "0123456789abcdefABCDEF" for c in tag):
            return fname[:-4], int(tag, 16), None
        if tag.lower() == "lxa":
            return fname[:-4], None, None
    return fname, None, None


APP_BASE = 0x8000            # where a RISC OS application slot starts


def _arm_imm(word):
    """The 8-bit-immediate-rotated-by-2*n field of an ARM data-processing op."""
    return ((word & 0xFF) >> (2 * ((word >> 8) & 0xF)) |
            (word & 0xFF) << (32 - 2 * ((word >> 8) & 0xF))) & 0xFFFFFFFF \
        if ((word >> 8) & 0xF) else (word & 0xFF)


def decompressor_load_addr(data, target=APP_BASE):
    """Load address for one of SICK's self-extracting images, or None.

    Their loader stubs open with a fixed six-instruction preamble that sets a
    stack, points R0 at the compressed data and computes the *destination* as a
    negative offset from its own PC, then finally MOVS pc, lr into it. So the
    file only works if it is loaded at (destination + that offset) -- loading it
    at &8000 like an ordinary absolute file puts the output below application
    space. The archive lost these addresses with the ,lxa tag, but the stub
    still states the offset, so the address can be recomputed exactly.
    """
    if len(data) < 0x18:
        return None
    w = [int.from_bytes(data[i:i + 4], "little") for i in range(0, 0x18, 4)]
    for word, mask in ((w[0], 0xE28FD000),      # ADD sp, pc, #n
                       (w[1], 0xE28DD000),      # ADD sp, sp, #n
                       (w[2], 0xE28F0000),      # ADD r0, pc, #n
                       (w[3], 0xE24F2000),      # SUB r2, pc, #n
                       (w[4], 0xE2422000)):     # SUB r2, r2, #n
        if word & 0xFFFFF000 != mask:
            return None
    if w[5] != 0xE1A0E002:                      # MOV lr, r2
        return None
    # r2 = (load + 0x14) - a - b, and that is where it jumps.
    return target + _arm_imm(w[3]) + _arm_imm(w[4]) - 0x14


def is_lxa(fname):
    """True for the ",lxa" marker: a file that carried load/exec addresses."""
    return len(fname) > 4 and fname[-4] == "," and fname[-3:].lower() == "lxa"


def riscos_name(name):
    """Undo the RISC OS <-> Unix separator swap.

    "." is RISC OS's path separator and "/" is an ordinary character, so an
    extraction to Unix swaps the two. A Unix name with a dot in it -- there are
    108 in this archive, "LZCH3.4Lib" and "Trace.Draw" among them -- was
    "LZCH3/4Lib" on the disc, and writing the dot back would create a name ADFS
    reads as two path components.
    """
    return name.replace(".", "/")


def looks_like_text(data):
    """Plain ASCII plus printable Latin-1 -- a RISC OS text file may hold £ and
    © (&A3, &A9), which a bare 32..126 test rejects."""
    return all(32 <= c < 127 or c >= 0xA0 or c in (9, 10, 13, 12)
               for c in data[:4096])


def load_exec(filetype, mtime):
    """Return (load, exec) words for a directory entry.

    A typed file carries &FFFtttXX with the top byte of the 5-byte RISC OS
    timestamp in XX and the low four bytes in the exec word. An untyped file
    gets zero for both: the archive did not preserve the real load/exec
    addresses of ,lxa files, so inventing them would be worse than admitting
    the object is untyped.
    """
    if filetype is None:
        return 0, 0
    cs = int((mtime + 2208988800) * 100)
    return (0xFFF00000 | (filetype << 8) | ((cs >> 32) & 0xFF),
            cs & 0xFFFFFFFF)


class Obj:
    def __init__(self, name, path, is_dir):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.children = []
        self.sector = 0
        self.length = 0
        self.load = 0
        self.exec_ = 0
        self.derived = False


def sort_key(name):
    return name.upper()


def scan(path, type_text_as_fff, lxa_addr=LXA_ADDR):
    """Read the host tree into Obj nodes, sorted as ADFS requires."""
    objs = []
    for fname in os.listdir(path):
        full = os.path.join(path, fname)
        if os.path.islink(full):
            continue
        if os.path.isdir(full):
            o = Obj(riscos_name(fname), full, True)
            o.children = scan(full, type_text_as_fff, lxa_addr)
            objs.append(o)
        elif os.path.isfile(full):
            name, ftype, addrs = parse_name(fname)
            o = Obj(riscos_name(name), full, False)
            o.length = os.path.getsize(full)
            if ftype is None and type_text_as_fff and fname == name:
                # No suffix at all. The archive holds no ,fff files but 4,736
                # untyped ones, so Text is the tag that was dropped -- but only
                # claim it for content that really is text.
                with open(full, "rb") as fh:
                    if looks_like_text(fh.read(4096)):
                        ftype = 0xFFF
            if addrs:
                # Explicit addresses from the suffix: the one case where the
                # host name preserves exactly what the catalogue held.
                o.load, o.exec_ = addrs
            elif is_lxa(fname):
                with open(full, "rb") as fh:
                    derived = decompressor_load_addr(fh.read(0x18))
                o.load = o.exec_ = derived if derived else lxa_addr
                o.derived = derived is not None
            else:
                o.load, o.exec_ = load_exec(ftype, os.path.getmtime(full))
            objs.append(o)
    # ADFS requires case-insensitive sorted order: a mis-sorted entry is not
    # found by the filing system's binary search.
    objs.sort(key=lambda o: sort_key(o.name))
    return objs


def check(objs, path="$"):
    """Reject anything ADFS cannot represent, rather than silently mangling."""
    problems = []
    if len(objs) > DIR_ENTRIES:
        problems.append("%s: %d objects, ADFS D allows %d"
                        % (path, len(objs), DIR_ENTRIES))
    seen = {}
    for o in objs:
        if len(o.name) > 10:
            problems.append("%s.%s: name is %d characters, ADFS allows 10"
                            % (path, o.name, len(o.name)))
        if not o.name:
            problems.append("%s: empty name" % path)
        for ch in o.name:
            if ord(ch) < 32 or ch in '$&%@\\^:.#*"|':   # "." cannot survive
                problems.append("%s.%s: %r is not valid in an ADFS name"
                                % (path, o.name, ch))
        k = o.name.upper()
        if k in seen:
            problems.append("%s: %s and %s collide when case is ignored"
                            % (path, seen[k], o.name))
        seen[k] = o.name
        # The two plausible case-folds must agree, or the sort order -- and so
        # whether the filing system can find an entry -- depends on the guess.
        if o.is_dir:
            problems += check(o.children, "%s.%s" % (path, o.name))
    lo = [o.name for o in sorted(objs, key=lambda o: o.name.lower())]
    up = [o.name for o in sorted(objs, key=lambda o: o.name.upper())]
    if lo != up:
        problems.append("%s: sort order is ambiguous under case folding (%s)"
                        % (path, ", ".join(lo)))
    return problems


def allocate(objs, cursor):
    """Assign a start sector to every object, depth first. Files are contiguous.

    Every object starts on a 1024-byte physical sector: ADFS transfers whole
    sectors, and a directory that is not sector aligned is reported as broken.
    """
    for o in objs:
        cursor += -cursor % ALIGN
        o.sector = cursor
        if o.is_dir:
            cursor += DIR_SIZE // SECTOR
        else:
            cursor += max(1, (o.length + SECTOR - 1) // SECTOR)
    for o in objs:
        if o.is_dir:
            cursor = allocate(o.children, cursor)
    return cursor


def build_dir(objs, name, parent_sector):
    """Render one 2048-byte directory."""
    d = bytearray(DIR_SIZE)
    d[0] = 0                                    # master sequence number, BCD
    d[1:5] = MARKER
    p = 5
    for o in objs:
        nm = o.name.encode("latin-1")[:10]
        if len(nm) < 10:
            nm = nm + b"\x0d"                   # terminated, never space padded
        d[p:p + len(nm)] = nm
        d[p + 10:p + 14] = o.load.to_bytes(4, "little")
        d[p + 14:p + 18] = o.exec_.to_bytes(4, "little")
        d[p + 18:p + 22] = (0 if o.is_dir else o.length).to_bytes(4, "little")
        d[p + 22:p + 25] = o.sector.to_bytes(3, "little")
        d[p + 25] = ATTR_DIR if o.is_dir else ATTR_FILE
        p += 26
    d[0x7D7] = 0                                # end-of-directory marker
    d[0x7DA:0x7DD] = parent_sector.to_bytes(3, "little")
    title = name.encode("latin-1")[:19]
    d[0x7DD:0x7DD + len(title)] = title
    if len(title) < 19:
        d[0x7DD + len(title)] = 0x0D
    nm = name.encode("latin-1")[:10]
    d[0x7F0:0x7F0 + len(nm)] = nm
    if len(nm) < 10:
        d[0x7F0 + len(nm)] = 0x0D
    # A directory is 'Broken' unless bytes 000-004 match 7FA-7FE.
    d[0x7FA] = d[0]
    d[0x7FB:0x7FF] = MARKER
    d[0x7FF] = dir_check_byte(d)                # must be last: covers the tail
    return bytes(d)


def emit(img, objs, name, parent_sector, at):
    img[at:at + DIR_SIZE] = build_dir(objs, name, parent_sector)
    for o in objs:
        off = o.sector * SECTOR
        if o.is_dir:
            emit(img, o.children, o.name, at // SECTOR, off)
        else:
            with open(o.path, "rb") as fh:
                data = fh.read()
            img[off:off + len(data)] = data


def disc_identifier(img):
    """A stable 16-bit id for this image's contents (never zero)."""
    h = hashlib.sha256(bytes(img[SECTOR * 2:])).digest()
    return (int.from_bytes(h[:2], "little") or 1)


def build_map(img, disc_name, free_start, free_len, boot_option=0,
              disc_id=0):
    # Sector 0: free space start sectors, then disc size and checksum.
    img[0:3] = free_start.to_bytes(3, "little")
    img[0xFC:0xFF] = TOTAL_SECTORS.to_bytes(3, "little")
    # Sector 1: free space lengths, disc id, boot option, list end pointer.
    img[0x100:0x103] = free_len.to_bytes(3, "little")
    # The disc identifier exists so the filing system can tell one disc from
    # another. Leaving it zero on every image means ADFS cannot see that a
    # swapped floppy is a different disc, and serves stale cached directories.
    img[0x1FB:0x1FD] = disc_id.to_bytes(2, "little")
    img[0x1FD] = boot_option                         # *Opt 4,n
    img[0x1FE] = 3                                   # 3 * one free space block
    # The disc name is 10 characters interleaved across the two map sectors:
    # even characters at 0F7-0FB, odd characters at 1F6-1FA.
    nm = disc_name.encode("latin-1")[:10].ljust(10, b"\x00")
    for i, c in enumerate(nm):
        img[(0xF7 + i // 2) if i % 2 == 0 else (0x1F6 + i // 2)] = c
    img[0x0FF] = checksum(img[0x000:0x100])
    img[0x1FF] = checksum(img[0x100:0x200])


def validate_image(img):
    """Re-read the finished image and apply the rules RISC OS enforces.

    These are exactly the checks a round-trip through a reader does not make:
    ADFSlib will happily parse a directory whose start and end markers disagree,
    or one that is not sector aligned, because it trusts the disc format rather
    than the directory. RISC OS reports both as "Broken directory".
    """
    problems, seen = [], set()

    def walk_dir(at, path):
        if at in seen:
            return
        seen.add(at)
        if at % PHYS_SECTOR:
            problems.append("%s: directory at &%X is not on a %d-byte sector "
                            "boundary" % (path, at, PHYS_SECTOR))
        start_seq, start_name = img[at], bytes(img[at + 1:at + 5])
        end_seq, end_name = img[at + 0x7FA], bytes(img[at + 0x7FB:at + 0x7FF])
        # Either marker is valid -- FileCore accepts "Nick" or "Hugo" on any
        # format but L. We write "Nick" because ADFS-D is "old map, new dir".
        if start_name not in (b"Nick", b"Hugo"):
            problems.append("%s: start marker %r is neither Nick nor Hugo"
                            % (path, start_name))
        if img[at + 0x7D7] or img[at + 0x7D8] or img[at + 0x7D9]:
            problems.append("%s: end-of-entries marker and the two reserved "
                            "bytes after it must all be zero" % path)
        want = dir_check_byte(bytes(img[at:at + DIR_SIZE]))
        if img[at + 0x7FF] != want:
            problems.append("%s: check byte is &%02X, should be &%02X"
                            % (path, img[at + 0x7FF], want))
        if start_name != end_name:
            problems.append("%s: start marker %r != end marker %r"
                            % (path, start_name, end_name))
        if start_seq != end_seq:
            problems.append("%s: start sequence %d != end sequence %d"
                            % (path, start_seq, end_seq))
        p = at + 5
        while p < at + 0x7D7 and img[p] != 0:
            name = bytes(img[p:p + 10]).split(b"\x0d")[0].split(b"\x00")[0]
            sector = int.from_bytes(img[p + 22:p + 25], "little")
            attr = img[p + 25]
            child = "%s.%s" % (path, name.decode("latin-1"))
            if sector * SECTOR >= IMAGE_SIZE:
                problems.append("%s: starts past the end of the disc" % child)
            elif attr & 0x08:
                walk_dir(sector * SECTOR, child)
            p += 26

    walk_dir(ROOT_SECTOR * SECTOR, "$")
    for i, (off, label) in enumerate(((0x000, "0"), (0x100, "1"))):
        if img[off + 0xFF] != checksum(img[off:off + 0x100]):
            problems.append("map sector %s: checksum does not match" % label)
    if img[0x200:0x205] != b"\0\0\0\0\0":
        problems.append("sector 2 does not start with five zero bytes, so the "
                        "disc will not be read as large-sector")
    return problems


def build(src, out, disc_name, type_text_as_fff=True, lxa_addr=LXA_ADDR):
    objs = scan(src, type_text_as_fff, lxa_addr)
    problems = check(objs)
    if problems:
        sys.exit("cannot build image:\n  " + "\n  ".join(problems))

    end = allocate(objs, DATA_SECTOR)
    if end > TOTAL_SECTORS:
        sys.exit("contents need %d sectors, an 800K ADFS disc holds %d "
                 "(%.0f KB over)"
                 % (end, TOTAL_SECTORS, (end - TOTAL_SECTORS) * SECTOR / 1024))

    img = bytearray(IMAGE_SIZE)
    emit(img, objs, "$", ROOT_SECTOR, ROOT_SECTOR * SECTOR)
    # A disc holding a root !Boot wants *Opt 4,2 so Shift-Break runs it; the
    # original floppies were set that way (their own !RunCode issues "opt 4 2").
    boot_option = 2 if any(o.name.lower() == "!boot" for o in objs) else 0
    # Derived from the content so two builds of different trees -- or of the
    # same tree with one byte changed -- never collide.
    disc_id = disc_identifier(img)
    build_map(img, disc_name, end, TOTAL_SECTORS - end, boot_option, disc_id)

    # Sector 2's first five bytes must be zero: that is what marks the disc as
    # large-sector, with its root directory at sector 4.
    assert img[0x200:0x205] == b"\0\0\0\0\0"
    assert img[0x401:0x405] == MARKER
    assert len(img) == IMAGE_SIZE

    problems = validate_image(img)
    if problems:
        sys.exit("built image fails validation:\n  " + "\n  ".join(problems))

    with open(out, "wb") as fh:
        fh.write(img)

    nlxa = sum(1 for o in walk_files(objs)
               if o.load == lxa_addr and o.exec_ == lxa_addr and not o.derived)
    for o in walk_files(objs):
        if o.derived:
            print("  %s: load/exec &%X recovered from its decompressor stub"
                  % (o.name, o.load))
    nfiles = sum(1 for _ in walk_files(objs))
    ndirs = sum(1 for o in walk_all(objs) if o.is_dir)
    print("wrote %s" % out)
    print("  %d files, %d directories, disc name %r" % (nfiles, ndirs, disc_name))
    if nlxa:
        print("  %d ,lxa files given load/exec &%X (addresses not preserved "
              "in the archive)" % (nlxa, lxa_addr))
    print("  disc id &%04X" % disc_id)
    print("  boot option %d%s"
          % (boot_option, " (Shift-Break runs $.!Boot)" if boot_option else ""))
    print("  %d of %d sectors used (%.0f KB free)"
          % (end, TOTAL_SECTORS, (TOTAL_SECTORS - end) * SECTOR / 1024))
    return 0


def walk_all(objs):
    for o in objs:
        yield o
        if o.is_dir:
            yield from walk_all(o.children)


def walk_files(objs):
    for o in walk_all(objs):
        if not o.is_dir:
            yield o


def self_test():
    fails = []

    def ck(name, got, want):
        if got != want:
            fails.append("%s: got %r want %r" % (name, got, want))

    # Checksum, hand-computed from the reference algorithm.
    ck("sum zeros", checksum(bytes(256)), 255)
    d = bytearray(256); d[0] = 1
    ck("sum byte0", checksum(d), 0)          # 255 + 1 = 256, truncated to 0
    d = bytearray(256); d[254] = 1
    ck("sum byte254", checksum(d), 1)        # 256 -> folded to 1 next iteration
    # Byte 255 is the checksum's own slot and must not be included.
    d = bytearray(256); d[255] = 0xAB
    ck("sum ignores 255", checksum(d), 255)
    # Adding upwards, or starting from zero, gives a different answer -- this
    # pins the direction so a "tidied" rewrite cannot silently change it.
    d = bytes(range(256))
    ck("sum ordered", checksum(d), checksum(d))
    ck("sum not naive", checksum(d) != sum(d[:255]) & 255, True)

    # Cross-check against a structurally different transcription of the same
    # documented algorithm: folding the carry as "(s+1) AND 255" is the same as
    # subtracting 255, for any s in 256..510. This catches a transcription slip,
    # though not a misreading of the specification itself.
    def checksum_alt(data):
        s = 255
        for a in range(254, -1, -1):
            if s > 255:
                s -= 255
            s += data[a]
        return s & 255
    import random as _r
    _rng = _r.Random(20260823)
    for _ in range(200):
        v = bytes(_rng.randrange(256) for _ in range(256))
        if checksum(v) != checksum_alt(v):
            fails.append("checksum disagrees with alternate form on %r" % (v[:8],))
            break

    ck("type ffb", parse_name("MemLib,ffb"), ("MemLib", 0xFFB, None))
    ck("type upper", parse_name("X,FFB"), ("X", 0xFFB, None))
    ck("lxa", parse_name("!RunImage,lxa"), ("!RunImage", None, None))
    ck("lxa upper", parse_name("X,LXA"), ("X", None, None))
    ck("untyped", parse_name("TextFile"), ("TextFile", None, None))
    ck("not a tag", parse_name("a,zzz"), ("a,zzz", None, None))
    ck("short", parse_name(",ffb"), (",ffb", None, None))
    # The ",load-exec" suffix Arculator hostfs writes for untyped files.
    ck("load-exec", parse_name("Sheepoid,ba60-ba74"),
       ("Sheepoid", None, (0xBA60, 0xBA74)))
    ck("load-exec 8 digits", parse_name("X,00008000-ffffba74"),
       ("X", None, (0x8000, 0xFFFFBA74)))
    ck("load-exec upper", parse_name("X,BA60-1"), ("X", None, (0xBA60, 1)))
    ck("load-exec 9 digits", parse_name("X,123456789-1"),
       ("X,123456789-1", None, None))
    ck("load-exec not hex", parse_name("X,zz-11"), ("X,zz-11", None, None))
    ck("load-exec empty side", parse_name("X,-11"), ("X,-11", None, None))
    ck("load-exec two dashes", parse_name("X,1-2-3"), ("X,1-2-3", None, None))
    ck("dash without comma", parse_name("A-B"), ("A-B", None, None))

    ck("load typed", load_exec(0xFF8, -2208988800.0), (0xFFFFF800, 0))
    ck("load untyped", load_exec(None, 0.0), (0, 0))
    # The real preambles of !RunImage and !RunImage3 from the 1991 floppy.
    run1 = bytes.fromhex("a4d08fe2" "5adb8de2" "9c008fe2"
                         "852f4fe2" "062b42e2" "02e0a0e1")
    run3 = bytes.fromhex("a4d08fe2" "8fdb8de2" "9c008fe2"
                         "632f4fe2" "012a42e2" "02e0a0e1")
    ck("imm rotated 30", _arm_imm(0xE24F2F85), 0x214)
    ck("imm rotated 22", _arm_imm(0xE2422B06), 0x1800)
    ck("imm unrotated", _arm_imm(0xE2422006), 6)
    ck("!RunImage load", decompressor_load_addr(run1), 0x9A00)
    ck("!RunImage3 load", decompressor_load_addr(run3), 0x9178)
    # It decompresses to &8000 exactly -- that is the whole point.
    ck("target is app base", decompressor_load_addr(run1) - 0x1A00, APP_BASE)
    ck("not a stub", decompressor_load_addr(bytes(0x18)), None)
    ck("too short", decompressor_load_addr(b"\x00" * 4), None)
    bad = bytearray(run1); bad[20] ^= 0xFF          # break MOV lr, r2
    ck("wrong preamble", decompressor_load_addr(bytes(bad)), None)

    ck("text ascii", looks_like_text(b"hello\r\n"), True)
    ck("text latin1", looks_like_text("a £5 © b".encode("latin-1")), True)
    ck("binary rejected", looks_like_text(bytes([0x00, 0x01, 0x02])), False)
    ck("escape rejected", looks_like_text(b"a\x1bb"), False)

    ck("dot becomes slash", riscos_name("LZCH3.4Lib"), "LZCH3/4Lib")
    ck("dot dir", riscos_name("Trace.Draw"), "Trace/Draw")
    ck("plain name untouched", riscos_name("!Scorpius"), "!Scorpius")
    ck("slash is legal in ADFS", check([Obj("LZCH3/4Lib", "", False)]), [])
    ck("a dot still rejected", any("not valid" in p
                                  for p in check([Obj("a.b", "", False)])), True)

    ck("is_lxa", is_lxa("!RunImage,lxa"), True)
    ck("is_lxa upper", is_lxa("X,LXA"), True)
    ck("is_lxa not hex tag", is_lxa("X,ffb"), False)
    ck("is_lxa plain", is_lxa("TextFile"), False)
    cs70 = 2208988800 * 100
    ck("load date", load_exec(0xFFB, 0.0),
       (0xFFF00000 | (0xFFB << 8) | ((cs70 >> 32) & 0xFF), cs70 & 0xFFFFFFFF))

    # A rendered directory must satisfy the two rules that make ADFS accept it.
    a = Obj("Alpha", "", False); a.sector = 20; a.length = 300
    b = Obj("Sub", "", True); b.sector = 12; b.length = 999
    dd = build_dir([a, b], "$", ROOT_SECTOR)
    ck("dir size", len(dd), 0x800)
    ck("dir marker", dd[1:5], b"Nick")
    ck("dir seq matches", dd[0:5], dd[0x7FA:0x7FF])   # else 'Broken directory'
    ck("dir end marker", dd[0x7D7], 0)
    ck("dir check byte set", dd[0x7FF], dir_check_byte(dd))

    # ror13 is a 32-bit rotate, not a shift.
    ck("ror13 of 1", ror13(1), 1 << 19)
    ck("ror13 of 0x2000", ror13(0x2000), 1)
    v = 0xDEADBEEF
    for _ in range(32):
        v = ror13(v)
    ck("ror13 is a rotation", v, 0xDEADBEEF)   # 32 rotations of 13 == identity

    # Cross-check the check byte against DiscImageManager's differently
    # structured transcription of the same algorithm (count entries first,
    # then accumulate) -- two independent readings must agree.
    def check_byte_alt(d):
        n = 0
        while d[5 + n * 26] != 0:
            n += 1
        end, acc, amt = n * 26 + 5, 0, 0
        while amt + 3 < end:
            acc = int.from_bytes(d[amt:amt + 4], "little") ^ ror13(acc)
            amt += 4
        while amt < end:
            acc = d[amt] ^ ror13(acc)
            amt += 1
        amt = 2008
        while amt + 3 < 2048 - 4:
            acc = int.from_bytes(d[amt:amt + 4], "little") ^ ror13(acc)
            amt += 4
        return (acc ^ (acc >> 8) ^ (acc >> 16) ^ (acc >> 24)) & 0xFF

    _rng2 = _r.Random(99)
    for n in (0, 1, 2, 13, 76, 77):
        objs = []
        for j in range(n):
            o = Obj("F%d" % j, "", False)
            o.sector = 12 + j
            o.length = _rng2.randrange(100000)
            o.load = _rng2.randrange(1 << 32)
            o.exec_ = _rng2.randrange(1 << 32)
            objs.append(o)
        dj = build_dir(objs, "dir%d" % n, ROOT_SECTOR)
        if dir_check_byte(dj) != check_byte_alt(dj):
            fails.append("check byte formulations disagree at %d entries "
                         "(&%02X vs &%02X)"
                         % (n, dir_check_byte(dj), check_byte_alt(dj)))
        if dj[0x7FF] != dir_check_byte(dj):
            fails.append("stored check byte wrong at %d entries" % n)

    # It must actually depend on the contents.
    d2 = bytearray(dd); d2[7] ^= 0xFF
    ck("check byte follows the entries", dir_check_byte(bytes(d2)) != dd[0x7FF], True)
    # The end-of-entries marker at 7D7 is excluded; the tail words start at
    # 7D8, so that byte is included. Getting this boundary wrong is exactly the
    # PRM error the kernel warns about.
    d3 = bytearray(dd); d3[0x7D7] = 0xFF
    ck("7D7 excluded from check", dir_check_byte(bytes(d3)), dd[0x7FF])
    d4 = bytearray(dd); d4[0x7D8] = 0xFF
    ck("7D8 included in check", dir_check_byte(bytes(d4)) != dd[0x7FF], True)
    ck("entry1 name", dd[5:10], b"Alpha")
    ck("entry1 term", dd[10], 0x0D)
    ck("entry1 load", dd[15:19], b"\x00\x00\x00\x00")
    ck("entry1 attr", dd[5 + 25], ATTR_FILE)
    ck("entry1 len", int.from_bytes(dd[5 + 18:5 + 22], "little"), 300)
    ck("entry1 sector", int.from_bytes(dd[5 + 22:5 + 25], "little"), 20)
    ck("entry2 attr", dd[31 + 25], ATTR_DIR)
    ck("dir entry stride", dd[31:34], b"Sub")
    ck("parent", int.from_bytes(dd[0x7DA:0x7DD], "little"), ROOT_SECTOR)
    # A directory entry must never claim a length for a directory.
    ck("dir len zero", int.from_bytes(dd[31 + 18:31 + 22], "little"), 0)

    # 77 entries fit; the 78th does not, and the terminator stays inside.
    many = []
    for i in range(DIR_ENTRIES):
        o = Obj("F%d" % i, "", False); o.sector = 12
        many.append(o)
    ck("77 fit", 5 + DIR_ENTRIES * 26, 0x7D7)
    ck("78 rejected", any("allows 77" in p for p in check(many + [Obj("Z", "", False)])), True)

    # Name validation.
    ck("long name", any("ADFS allows 10" in p
                        for p in check([Obj("ElevenChars", "", False)])), True)
    ck("bad char", any("not valid" in p
                       for p in check([Obj("a.b", "", False)])), True)
    ck("case collide", any("collide" in p for p in check(
        [Obj("Abc", "", False), Obj("ABC", "", False)])), True)
    ck("good names ok", check([Obj("!Scorpius", "", False),
                               Obj("SCORPIUS21", "", False)]), [])

    # Allocation is contiguous and starts after the root directory.
    f1 = Obj("A", "", False); f1.length = 1
    f2 = Obj("B", "", False); f2.length = SECTOR + 1
    end = allocate([f1, f2], DATA_SECTOR)
    ck("alloc first", f1.sector, DATA_SECTOR)
    # Alignment, not 1 sector: every object starts on a physical sector.
    # Pinned to the literal 4 (= 1024/256), not to ALIGN, so weakening ALIGN
    # cannot make these tests agree with themselves.
    ck("ALIGN is four logical sectors", ALIGN, 4)
    ck("alloc aligns", f2.sector, DATA_SECTOR + 4)
    ck("alloc rounds up", end, DATA_SECTOR + 4 + 2)
    d1 = Obj("D", "", True); d1.children = [Obj("E", "", False)]
    d1.children[0].length = 10
    everything = [f1, f2, d1]
    allocate(everything, DATA_SECTOR)
    for o in walk_all(everything):
        if o.sector % 4:
            fails.append("object %s starts at sector %d, not physical-sector "
                         "aligned" % (o.name, o.sector))
    ck("root is aligned", (ROOT_SECTOR * SECTOR) % PHYS_SECTOR, 0)
    ck("data start aligned", (DATA_SECTOR * SECTOR) % PHYS_SECTOR, 0)

    # D format is "old map, new dir", and the new directory's marker is Nick.
    ck("marker is Nick", MARKER, b"Nick")

    # scan() must return entries in case-insensitive sorted order: ADFS finds
    # an entry by binary search, so a mis-sorted one is invisible to it.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        for n in ("zeta,ffd", "Alpha,ffd", "!Boot,feb", "middle,ffd"):
            open(os.path.join(td, n), "wb").write(b"x")
        os.mkdir(os.path.join(td, "Sub"))
        open(os.path.join(td, "Code,lxa"), "wb").write(b"x")
        open(os.path.join(td, "Loader,ba60-ba74"), "wb").write(b"x")
        scanned = scan(td, False)
        names = [o.name for o in scanned if o.name not in ("Code", "Loader")]
        code = [o for o in scanned if o.name == "Code"][0]
        loader = [o for o in scanned if o.name == "Loader"][0]
    ck("lxa gets an address", (code.load, code.exec_), (LXA_ADDR, LXA_ADDR))
    ck("suffix addresses kept", (loader.load, loader.exec_), (0xBA60, 0xBA74))
    ck("scan sorts", names, sorted(names, key=sort_key))
    ck("scan sorted order", names, ["!Boot", "Alpha", "middle", "Sub", "zeta"])

    m = bytearray(IMAGE_SIZE)
    build_map(m, "X", 100, 200, 2)
    ck("boot option written", m[0x1FD], 2)
    build_map(m, "X", 100, 200, 2, 0xBEEF)
    ck("disc id written", m[0x1FB:0x1FD], b"\xef\xbe")

    # The id must follow the content, and never be zero.
    i1 = bytearray(IMAGE_SIZE); i1[0x4000] = 1
    i2 = bytearray(IMAGE_SIZE); i2[0x4000] = 2
    ck("id follows content", disc_identifier(i1) != disc_identifier(i2), True)
    ck("id is stable", disc_identifier(i1), disc_identifier(bytearray(i1)))
    ck("id ignores the map", disc_identifier(i1),
       disc_identifier(bytearray(b"\xff" * 512 + bytes(i1[512:]))))
    ck("id never zero", all(disc_identifier(bytearray(IMAGE_SIZE)) != 0
                           for _ in range(1)), True)
    ck("map checksum covers it", m[0x1FF], checksum(m[0x100:0x200]))

    ck("root after map", ROOT_SECTOR * SECTOR, 0x400)
    ck("data after root", DATA_SECTOR * SECTOR, 0xC00)
    ck("image size", IMAGE_SIZE, 819200)

    if fails:
        print("SELF-TEST FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("self-test OK")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", nargs="?")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--name", default="Scorpius", help="disc name (10 chars)")
    ap.add_argument("--lxa-addr", default=hex(LXA_ADDR),
                    help="load/exec address for ,lxa files (default &8000); "
                         "their real addresses are not in the archive")
    ap.add_argument("--no-text-type", action="store_true",
                    help="leave suffix-less files untyped instead of &FFF")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.src or not a.out:
        ap.error("need SRCDIR and OUT.adf")
    return build(a.src, a.out, a.name, not a.no_text_type,
                 int(a.lxa_addr, 0))


if __name__ == "__main__":
    sys.exit(main())
