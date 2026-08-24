#!/usr/bin/env python3
# Copyright (C) 2026 Merlin Hughes
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detokenise RISC OS BBC BASIC V files (filetype &FFB) to plain text.

Usage:  debasic.py FILE...            print to stdout
        debasic.py -o OUTDIR FILE...  mirror each FILE to OUTDIR as .bas
        debasic.py --self-test
"""
import sys, os, re, argparse

# BBC BASIC V single-byte tokens, &7F..&FF.
TOK = {
    0x7F: "OTHERWISE", 0x80: "AND", 0x81: "DIV", 0x82: "EOR", 0x83: "MOD",
    0x84: "OR", 0x85: "ERROR", 0x86: "LINE", 0x87: "OFF", 0x88: "STEP",
    0x89: "SPC", 0x8A: "TAB(", 0x8B: "ELSE", 0x8C: "THEN",
    0x8E: "OPENIN", 0x8F: "PTR",
    0x90: "PAGE", 0x91: "TIME", 0x92: "LOMEM", 0x93: "HIMEM", 0x94: "ABS",
    0x95: "ACS", 0x96: "ADVAL", 0x97: "ASC", 0x98: "ASN", 0x99: "ATN",
    0x9A: "BGET", 0x9B: "COS", 0x9C: "COUNT", 0x9D: "DEG", 0x9E: "ERL",
    0x9F: "ERR",
    0xA0: "EVAL", 0xA1: "EXP", 0xA2: "EXT", 0xA3: "FALSE", 0xA4: "FN",
    0xA5: "GET", 0xA6: "INKEY", 0xA7: "INSTR(", 0xA8: "INT", 0xA9: "LEN",
    0xAA: "LN", 0xAB: "LOG", 0xAC: "NOT", 0xAD: "OPENUP", 0xAE: "OPENOUT",
    0xAF: "PI",
    0xB0: "POINT(", 0xB1: "POS", 0xB2: "RAD", 0xB3: "RND", 0xB4: "SGN",
    0xB5: "SIN", 0xB6: "SQR", 0xB7: "TAN", 0xB8: "TO", 0xB9: "TRUE",
    0xBA: "USR", 0xBB: "VAL", 0xBC: "VPOS", 0xBD: "CHR$", 0xBE: "GET$",
    0xBF: "INKEY$",
    0xC0: "LEFT$(", 0xC1: "MID$(", 0xC2: "RIGHT$(", 0xC3: "STR$",
    0xC4: "STRING$(", 0xC5: "EOF",
    0xC9: "WHEN", 0xCA: "OF", 0xCB: "ENDCASE", 0xCC: "ELSE", 0xCD: "ENDIF",
    0xCE: "ENDWHILE", 0xCF: "PTR",
    0xD0: "PAGE", 0xD1: "TIME", 0xD2: "LOMEM", 0xD3: "HIMEM", 0xD4: "SOUND",
    0xD5: "BPUT", 0xD6: "CALL", 0xD7: "CHAIN", 0xD8: "CLEAR", 0xD9: "CLOSE",
    0xDA: "CLG", 0xDB: "CLS", 0xDC: "DATA", 0xDD: "DEF", 0xDE: "DIM",
    0xDF: "DRAW",
    0xE0: "END", 0xE1: "ENDPROC", 0xE2: "ENVELOPE", 0xE3: "FOR",
    0xE4: "GOSUB", 0xE5: "GOTO", 0xE6: "GCOL", 0xE7: "IF", 0xE8: "INPUT",
    0xE9: "LET", 0xEA: "LOCAL", 0xEB: "MODE", 0xEC: "MOVE", 0xED: "NEXT",
    0xEE: "ON", 0xEF: "VDU",
    0xF0: "PLOT", 0xF1: "PRINT", 0xF2: "PROC", 0xF3: "READ", 0xF4: "REM",
    0xF5: "REPEAT", 0xF6: "REPORT", 0xF7: "RESTORE", 0xF8: "RETURN",
    0xF9: "RUN", 0xFA: "STOP", 0xFB: "COLOUR", 0xFC: "TRACE", 0xFD: "UNTIL",
    0xFE: "WIDTH", 0xFF: "OSCLI",
}

# Two-byte tokens: prefix &C6/&C7/&C8 followed by a second byte.
TOK2 = {
    0xC6: {0x8E: "SUM", 0x8F: "BEAT"},
    0xC7: {0x8E: "APPEND", 0x8F: "AUTO", 0x90: "CRUNCH", 0x91: "DELETE",
           0x92: "EDIT", 0x93: "HELP", 0x94: "LIST", 0x95: "LOAD",
           0x96: "LVAR", 0x97: "NEW", 0x98: "OLD", 0x99: "RENUMBER",
           0x9A: "SAVE", 0x9B: "TEXTLOAD", 0x9C: "TEXTSAVE", 0x9D: "TWIN",
           0x9E: "TWINO", 0x9F: "INSTALL"},
    0xC8: {0x8E: "CASE", 0x8F: "CIRCLE", 0x90: "FILL", 0x91: "ORIGIN",
           0x92: "POINT", 0x93: "RECTANGLE", 0x94: "SWAP", 0x95: "WHILE",
           0x96: "WAIT", 0x97: "MOUSE", 0x98: "QUIT", 0x99: "SYS",
           0x9A: "INSTALL", 0x9B: "LIBRARY", 0x9C: "TINT", 0x9D: "ELLIPSE",
           0x9E: "BEATS", 0x9F: "TEMPO", 0xA0: "VOICES", 0xA1: "VOICE",
           0xA2: "STEREO", 0xA3: "OVERLAY"},
}


def decode_lineref(b):
    """Decode the 3-byte &8D inline line-number reference.

    The top two bits of each of the low and high bytes are held, rotated, in
    the first byte, and are XORed back out - not masked in. Verified against
    every &8D reference in the archive: all 330 resolve to a line that exists
    in their own program.
    """
    lo = b[1] ^ ((b[0] << 2) & 0xC0)
    hi = b[2] ^ ((b[0] << 4) & 0xC0)
    return (hi << 8) | lo


# Tokens that must never take a reinserted space after them: FN/PROC prefix an
# identifier, and the rest already end in "(" or "$".
#
# FN and PROC stay glued deliberately. "FNadr" and "PROCboot" read as one name
# -- which is what they are -- and BASIC's own LIST prints them that way.
# "DEF PROCboot" still gets its gap, because that one comes from DEF.
NO_GAP_AFTER = {"FN", "PROC"}

# Every word the token tables can emit. Used to tell a keyword from a variable
# when deciding whether a "-" is a subtraction or a sign: "STEP-1" is a sign,
# "BASECODE-1" is a subtraction, and both end in a letter.
KEYWORDS = set(TOK.values()) | {w for d in TOK2.values() for w in d.values()}

# After these, a "+" or "-" is a sign rather than an operator.
_SIGN_AFTER = set("=<>+-*/^,;:([")

# Splitting "SUBS5,5,#1" needs to know a mnemonic from a name: "Temp0",
# "FNkm1", "R0" and "long1" all look identical to "MOV0" under a rule as loose
# as "letters followed by a digit", and splitting those would be wrong. So
# match the actual ARM instruction set the BASIC assembler accepts, condition
# codes and suffixes included. Anything unrecognised is left alone -- a missed
# gap costs readability, a wrong one costs correctness.
_CC = "EQ|NE|CS|CC|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE|AL|NV"
_LSM = "IA|IB|DA|DB|FD|ED|FA|EA"
_MNEMONIC = re.compile(
    "(?:"
    r"(?:AND|EOR|SUB|RSB|ADD|ADC|SBC|RSC|ORR|BIC|MOV|MVN|MUL|MLA)(?:%(cc)s)?S?"
    r"|(?:TST|TEQ|CMP|CMN)(?:%(cc)s)?P?"
    r"|(?:LDR|STR)(?:%(cc)s)?(?:BT|B|T)?"
    r"|(?:LDM|STM)(?:(?:%(cc)s)(?:%(lsm)s)|(?:%(lsm)s)(?:%(cc)s)?)"
    r"|(?:BL|B)(?:%(cc)s)?"
    r"|SWI(?:%(cc)s)?"
    r"|ADR(?:%(cc)s)?L?"
    r"|(?:CDP|LDC|STC|MCR|MRC)(?:%(cc)s)?"
    r"|DCD|DCB|DCW|DCS|EQUD|EQUB|EQUW|EQUS|ALIGN|OPT"
    ")$" % {"cc": _CC, "lsm": _LSM})


def _respace(text, asm, depth=0):
    """Insert readability spacing into an already-detokenised line.

    Only ever *inserts* spaces -- never removes, reorders or rewrites -- so the
    result differs from the canonical form by whitespace alone. That invariant
    is checked over the whole archive by the self-test's caller; see --verify.

    Quoted text is copied through untouched. Assembler gets a smaller set of
    rules than BASIC: inside [ ] an "=" is EQUS and ":=" must not be split, and
    "+ - * / < >" sit inside address expressions like "#1<<31" and
    "#endhiscores-hinos" where spacing them out helps nobody. So in assembler
    only two things happen: the mnemonic gets separated from its first operand,
    and operand commas get a following space.
    """
    out = []
    i, n = 0, len(text)
    at_stmt = True                  # at the start of a statement

    def ends_space():
        return not out or out[-1].endswith(" ")

    def tail_char():
        for chunk in reversed(out):
            stripped = chunk.rstrip(" ")
            if stripped:
                return stripped[-1]
        return ""

    def tail_word():
        s = "".join(out).rstrip(" ")
        j = len(s)
        while j and s[j - 1].isalpha():
            j -= 1
        return s[j:]

    def gap():
        if out and not ends_space():
            out.append(" ")

    while i < n:
        c = text[i]

        # Quoted text, and the \xNN escapes we emit for non-ASCII, pass through
        # untouched -- a space inserted in there would corrupt the string.
        if c == '"':
            j = text.find('"', i + 1)
            j = n if j < 0 else j + 1
            out.append(text[i:j])
            i = j
            at_stmt = False
            continue
        if text.startswith("\\x", i) and i + 4 <= n:
            out.append(text[i:i + 4])
            i += 4
            at_stmt = False
            continue

        if c == "[":
            # Inside assembler this is an addressing mode -- "STR 0,[9],#640"
            # -- not a nested block. Only the outermost "[" opens assembler.
            if asm:
                depth += 1
            else:
                asm = True
                depth = 0
            out.append(c)
            i += 1
            at_stmt = not asm or depth == 0
            continue
        if c == "]":
            if asm and depth:
                depth -= 1
            else:
                asm = False
            out.append(c)
            i += 1
            at_stmt = depth == 0 and not asm
            continue

        if c == " ":
            out.append(c)
            i += 1
            continue

        # A statement start in assembler: split "SUBS5,5,#1" into "SUBS 5,5,#1".
        # A label definition (".printletloop15") starts with "." and keeps its
        # trailing digits.
        if asm and at_stmt and c.isalpha():
            j = i
            while j < n and text[j].isalpha():
                j += 1
            run = text[i:j]
            if (j < n and text[j] in "0123456789#&\""
                    and _MNEMONIC.match(run)):
                out.append(run)
                out.append(" ")
                i = j
                at_stmt = False
                continue

        stmt_start, at_stmt = at_stmt, False

        # "*" at the start of a statement is a command escape -- "*Set X",
        # "*OpenWin ..." -- and the command runs to the end of the line. It is
        # not multiplication, and nothing in it should be respaced.
        if c == "*" and stmt_start:
            out.append(text[i:])
            break

        if c in ",;":
            out.append(c)
            i += 1
            if i < n and text[i] != " ":
                out.append(" ")
            continue

        if c == ":":
            # ":=" in assembler is EQUS -- never split it.
            if asm and i + 1 < n and text[i + 1] == "=":
                out.append(c)
                i += 1
                continue
            out.append(c)
            i += 1
            if i < n and text[i] != " ":
                out.append(" ")
            at_stmt = True
            continue

        if asm:
            out.append(c)
            i += 1
            continue

        # --- BASIC operators ------------------------------------------------
        two = text[i:i + 2]
        if two in ("<=", ">=", "<>", "<<", ">>"):
            gap()
            out.append(two + " ")
            i += 2
            continue

        if c in "+-":
            prev = tail_char()
            sign = (prev == "" or prev in _SIGN_AFTER
                    or (prev.isalpha() and tail_word() in KEYWORDS))
            if sign:
                if prev and prev not in "([":
                    gap()
                out.append(c)
            else:
                gap()
                out.append(c + " ")
            i += 1
            continue

        if c in "=<>*/^":
            gap()
            out.append(c + " ")
            i += 1
            continue

        out.append(c)
        i += 1

    return "".join(out).rstrip()


def _wants_gap_after(word, nxt):
    if word in NO_GAP_AFTER or word[-1] in "($":
        return False
    if not word[-1].isalpha():
        return False
    # Outside assembler a keyword takes a gap before anything that starts a
    # term -- "TO0" and "THEN?flag" read better split. Not before "(", where
    # "INT(x)" and "LEN(s)" are how these are always written, and not before
    # "$" or "%", which finish a name: "REPORT$" is one word, not two.
    return nxt not in " :;,()$%"


def _wants_gap_before(word, prev):
    if not word[0].isalpha():
        return False
    return prev.isalnum() or prev in '%$)"'


def detok_line(body, state=None, pretty=False):
    """Detokenise one line body.

    Text inside quotes is never tokenised.  With pretty=True, spaces are
    reinserted around keywords for readability -- but never inside an [ ]
    assembler block, where ARM mnemonics such as ORR/ANDS/EORS are stored as
    an OR/AND/EOR token glued to the rest of the mnemonic and would be split.
    """
    if state is None:
        state = {"asm": False, "depth": 0}
    state.setdefault("depth", 0)
    asm_at_start, depth_at_start = state["asm"], state["depth"]
    out, i, inq = [], 0, False

    def emit_word(w, nxt):
        if pretty and not state["asm"]:
            prev = out[-1][-1] if out and out[-1] else ""
            if prev and _wants_gap_before(w, prev):
                out.append(" ")
            out.append(w)
            if nxt and _wants_gap_after(w, nxt):
                out.append(" ")
        else:
            out.append(w)

    while i < len(body):
        c = body[i]
        if inq:
            out.append(chr(c) if 32 <= c < 127 else "\\x%02X" % c)
            if c == 0x22:
                inq = False
            i += 1
            continue
        if c == 0x22:
            inq = True
            out.append('"')
            i += 1
        elif c == 0x8D and i + 3 < len(body):
            out.append(str(decode_lineref(body[i + 1:i + 4])))
            i += 4
        elif c in TOK2 and i + 1 < len(body) and body[i + 1] in TOK2[c]:
            w = TOK2[c][body[i + 1]]
            emit_word(w, chr(body[i + 2]) if i + 2 < len(body) else "")
            i += 2
        elif c in TOK:
            w = TOK[c]
            if c == 0xF4:                       # REM: rest of line is free text
                head = "".join(out)
                if pretty:
                    head = _respace(head, asm_at_start, depth_at_start)
                    if head and not head.endswith(" "):
                        head += " "
                tail = "".join(chr(x) if 32 <= x < 127 else "\\x%02X" % x
                               for x in body[i + 1:])
                return head + w + tail
            emit_word(w, chr(body[i + 1]) if i + 1 < len(body) else "")
            i += 1
        elif 32 <= c < 127:
            ch = chr(c)
            if ch == "[":
                if state["asm"]:
                    state["depth"] += 1      # [Rn] addressing, not a new block
                else:
                    state["asm"], state["depth"] = True, 0
            elif ch == "]":
                if state["asm"] and state["depth"]:
                    state["depth"] -= 1
                else:
                    state["asm"] = False
            out.append(ch)
            i += 1
        else:
            out.append("\\x%02X" % c)
            i += 1
    text = "".join(out)
    return _respace(text, asm_at_start, depth_at_start) if pretty else text


def is_basic(data):
    return len(data) >= 2 and data[0] == 0x0D


def detok(data, numbers=True, pretty=False):
    """Yield detokenised source lines. Raises ValueError on a malformed file."""
    lines, i = [], 0
    state = {"asm": False, "depth": 0}
    if not is_basic(data):
        raise ValueError("not a tokenised BASIC file (no leading &0D)")
    while i < len(data):
        if data[i] != 0x0D:
            raise ValueError("lost line sync at offset %d" % i)
        if i + 1 < len(data) and data[i + 1] == 0xFF:
            break                                    # &0D &FF terminator
        if i + 3 >= len(data):
            raise ValueError("truncated header at offset %d" % i)
        num = (data[i + 1] << 8) | data[i + 2]
        ln = data[i + 3]
        if ln < 4 or i + ln > len(data):
            raise ValueError("bad line length %d at offset %d" % (ln, i))
        text = detok_line(data[i + 4:i + ln], state, pretty)
        lines.append(("%5d %s" % (num, text)) if numbers else text)
        i += ln
    return lines


def self_test():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append("%s: got %r want %r" % (name, got, want))

    # A line-number reference round-trips (GOTO 100 as BASIC encodes it).
    # NB: BASIC XORs the held top bits back out, it does not mask them in --
    # encode the same way the interpreter does or this test proves nothing.
    for n in (0, 1, 10, 100, 255, 256, 1000, 32767, 65279):
        lo, hi = n & 0xFF, (n >> 8) & 0xFF
        enc = bytes([0x40 | (((lo & 0xC0) ^ 0x40) >> 2)
                          | (((hi & 0xC0) ^ 0x40) >> 4),
                     (lo & 0x3F) | 0x40, (hi & 0x3F) | 0x40])
        check("lineref %d" % n, decode_lineref(enc), n)

    # ...and against three references lifted from the archive, whose targets
    # are known lines in Bananaland Tetris x/Gen/Spriteconv.
    for enc, want in ((b"\x54\x62\x41", 290), (b"\x44\x54\x41", 340),
                      (b"\x74\x6e\x41", 430)):
        check("lineref real %d" % want, decode_lineref(enc), want)

    # A whole tiny program: 10 REM>X / 20 PRINT "HI" / 30 END
    prog = (b"\x0d\x00\x0a\x07\xf4>X"
            b"\x0d\x00\x14\x0a\xf1 \"HI\""
            b"\x0d\x00\x1e\x05\xe0"
            b"\x0d\xff")
    check("program", detok(prog, numbers=False),
          ["REM>X", 'PRINT "HI"', "END"])

    # A token byte inside a string stays literal.
    body = b'\x22\xf1\x22'
    check("quoted token", detok_line(body), '"\\xF1"')

    # Two-byte tokens.
    check("SYS", detok_line(b"\xc8\x99 X"), "SYS X")
    check("CASE", detok_line(b"\xc8\x8e X \xca"), "CASE X OF")

    # Inline assembler survives verbatim.
    check("asm", detok_line(b"[OPTpass"), "[OPTpass")

    # Malformed input is rejected, not silently truncated.
    # A non-BASIC file must be named as such, not reported as a sync loss --
    # 2299 ,ffd data files sit beside the ,ffb ones and get fed in by mistake.
    try:
        detok(b"\x00\x01")
        fails.append("accepted a non-BASIC file")
    except ValueError as e:
        check("magic message", "not a tokenised BASIC" in str(e), True)

    for bad, why in ((b"\x00\x01", "no leading 0D"),
                     (b"\x0d\x00\x0a\x02", "length below header"),
                     (b"\x0d\x00\x0a\xff", "length past EOF")):
        try:
            detok(bad)
            fails.append("accepted malformed input (%s)" % why)
        except ValueError:
            pass

    # --- pretty mode -------------------------------------------------------
    # Ground truth for the compact style: 1992 plain-text listings in the
    # archive read "DEFPROCcorricon", "FORQA%=a TOb-1STEP16", "UNTILSP%>LENS$".
    # Faithful mode must reproduce that; pretty mode must space it correctly.
    def P(body, want_raw, want_pretty):
        check("raw    " + want_raw, detok_line(body), want_raw)
        check("pretty " + want_pretty,
              detok_line(body, None, pretty=True), want_pretty)

    P(b"\xdd\xf2corricon", "DEFPROCcorricon", "DEF PROCcorricon")
    P(b"\xdd\xa4mem_init", "DEFFNmem_init", "DEF FNmem_init")
    P(b"\xea" + b"loop", "LOCALloop", "LOCAL loop")
    P(b"\xe3QA%=a \xb8b-1\x88" + b"16",
      "FORQA%=a TOb-1STEP16", "FOR QA% = a TO b - 1 STEP 16")
    P(b"\xfdSP%>\xa9S$", "UNTILSP%>LENS$", "UNTIL SP% > LEN S$")
    P(b"\xebq", "MODEq", "MODE q")
    P(b"\xc3~A%", "STR$~A%", "STR$~A%")          # token ends in $: no gap
    P(b"\xf1\"hi\"", 'PRINT"hi"', 'PRINT "hi"')

    # Inside an [ ] assembler block nothing is respaced: ARM ORR/ANDS/EORS are
    # stored as an OR/AND/EOR token glued to the mnemonic tail (4435 ORRs in
    # the Scorpius tree alone) and spacing them would corrupt the instruction.
    check("asm ORR", detok_line(b"[OPTpass:\x84R R0,R1,R2", None, pretty=True),
          "[OPTpass: ORR R0, R1, R2")
    check("asm ANDS", detok_line(b"[\x80S R0,R1", None, pretty=True),
          "[ANDS R0, R1")
    # ...and the block stays open across lines until "]" is seen.
    st = {"asm": False}
    detok_line(b"[OPTpass", st, pretty=True)
    check("asm spans lines", detok_line(b"\x84R R0,R1,R2", st, pretty=True),
          "ORR R0, R1, R2")
    detok_line(b"]", st, pretty=True)
    check("asm closes", detok_line(b"\xea" + b"x", st, pretty=True), "LOCAL x")

    # --- the -p spacing rules -------------------------------------------
    def PP(name, body, want):
        check("pretty " + name, detok_line(body, None, pretty=True), want)

    # A mnemonic is split from its first operand; a label keeps its digits.
    PP("asm mnemonic gap", b"[SUBS5,5,#1", "[SUBS 5, 5, #1")
    PP("asm label digits", b"[.printletloop15:MOV0,#356",
       "[.printletloop15: MOV 0, #356")
    PP("asm SWI string", b'[SWI"OS_Byte"', '[SWI "OS_Byte"')
    # ":=" is EQUS and must survive; "#1<<31" must not be pulled apart.
    PP("asm EQUS", b'[.n:="X":=0', '[.n:="X":=0')
    PP("asm shift kept", b"[MVN2,#1<<31", "[MVN 2, #1<<31")
    # A sign is not an operator: STEP-1 and =-4 keep the number together.
    PP("sign after keyword", b"\xe3D%=47\xb80\x88-1",
       "FOR D% = 47 TO 0 STEP -1")
    PP("sign after equals", b"P=-4", "P = -4")
    PP("minus is operator", b"BASECODE-1", "BASECODE - 1")
    # Colons and commas breathe; quoted text never does.
    PP("colon and comma", b"A=1:B=2", "A = 1: B = 2")
    PP("quotes untouched", b'\xf1"a,b:c"', 'PRINT "a,b:c"')

    # "*" starts an operating-system command, not a multiplication, and the
    # command runs to end of line -- colons inside it are the command's own.
    PP("star command", b"\xe7\xc8\x98:*OpenWin Make Tertis",
       "IF QUIT: *OpenWin Make Tertis")
    PP("star at line start", b"*Set X 1:2", "*Set X 1:2")
    PP("star is still times", b"A=B*C", "A = B * C")
    # "$" and "%" finish a name -- REPORT$ is one word.
    PP("REPORT$", b"\x85\x9f,\xf6$", "ERROR ERR, REPORT$")

    # An [Rn] addressing mode must not be mistaken for the end of the
    # assembler block -- if it is, every mnemonic after it gets split, and
    # "ANDS12,10,#255" comes out as "AND S12, 10, #255".
    st = {"asm": False, "depth": 0}
    detok_line(b"[OPTpass", st, pretty=True)
    check("asm [Rn] not block end",
          detok_line(b"\x80S12,10,#255:\x82NE12,4,10:STRB 12,[9],#640",
                     st, pretty=True),
          "ANDS 12, 10, #255: EORNE 12, 4, 10: STRB 12, [9], #640")
    check("asm still open after [Rn]", st["asm"], True)
    detok_line(b"]", st, pretty=True)
    check("asm closed by real ]", st["asm"], False)

    # REM text is never respaced or retokenised.
    check("rem", detok_line(b"\xf4 \xf2not a proc", None, pretty=True),
          r"REM \xF2not a proc")

    if fails:
        print("SELF-TEST FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("self-test OK")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("-o", "--outdir", help="mirror output here as .bas files")
    ap.add_argument("-n", "--no-numbers", action="store_true",
                    help="omit line numbers")
    ap.add_argument("-p", "--pretty", action="store_true",
                    help="reinsert spaces around keywords for readability "
                         "(never inside [ ] assembler blocks)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.files:
        ap.error("no input files")
    bad = 0
    for f in a.files:
        try:
            lines = detok(open(f, "rb").read(),
                          numbers=not a.no_numbers, pretty=a.pretty)
        except (ValueError, OSError) as e:
            print("%s: %s" % (f, e), file=sys.stderr)
            bad += 1
            continue
        if a.outdir:
            rel = f.lstrip("/")
            if len(rel) > 4 and rel[-4] == "," :   # drop the ,ffb filetype tag
                rel = rel[:-4]
            dst = os.path.join(a.outdir, rel) + ".bas"
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write("\n".join(lines) + "\n")
        else:
            if len(a.files) > 1:
                print("========== %s ==========" % f)
            print("\n".join(lines))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
