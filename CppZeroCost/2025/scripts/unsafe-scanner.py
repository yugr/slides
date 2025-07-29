#!/usr/bin/python3

# Collects stats about usage of unsafe in Rust sources.
# This script is EXTREMELY primitive and imprecise.
# E.g. we completely ignore macros.
#
# You are supposed to run it in Rust compiler repo like this:
#   $ ./unsafe-scanner.py library/core

import os
import os.path
import re
import sys


class TokType:
    EOF = "EOF"
    LBRACE = "{"
    RBRACE = "}"
    FN = "fn"
    UNSAFE = "unsafe"
    USE = "use"
    SEMI = ";"
    OTHER = "OTHER"


class Location:
    def __init__(self, filename, line):
        self.filename = filename
        self.line = line

    def __str__(self):
        return f"{self.filename}:{self.line}"


class Token:
    def __init__(self, typ, text, loc):
        self.typ = typ
        self.text = text
        self.loc = Location(loc.filename, loc.line)

    def __str__(self):
        return f"'{self.text}' ({self.typ}, {self.loc})"


class LexerError(Exception):
    pass


class Lexer:
    def __init__(self, filename):
        with open(filename) as f:
            self.lines = [line.strip() for line in f.readlines()]

        self.filename = filename
        self.pos = 0
        self.next = None

    def _peek_impl(self):
        loc = Location(self.filename, self.pos + 1)

        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            # print(line)

            # Skip whites and comments

            line = re.sub(r"^\s*", "", line)

            if line.startswith("//"):
                line = ""
            elif line.startswith("/*"):
                start = 2
                while True:
                    line = self.lines[self.pos]
                    finish = line.find("*/", start)
                    if finish != -1:
                        line = line[finish + 2 :]
                        break
                    start = 0
                    self.pos += 1
                    loc.line += 1
                self.lines[self.pos] = line
                continue

            # Skip empty lines

            if not line:
                self.pos += 1
                loc.line += 1
                continue

            # Chars
            # TODO: byte chars: b'...'

            if line[0] == "'" and len(line) >= 3:
                # TODO: \xff
                # TODO: \\

                if line[1] != "\\" and line[2] == "'":
                    self.next = Token(TokType.OTHER, line[:3], loc)
                    line = line[3:]
                    break

                if line.startswith("'\\x"):  # '\x1f'
                    if len(line) < 5:
                        raise LexerError(f"{loc}: unable to parse hex char literal: {line}")
                    self.next = Token(TokType.OTHER, line[:5], loc)
                    line = line[5:]
                    break

                if line.startswith("'\\"):  # '\t'
                    if len(line) < 4:
                        raise LexerError(f"{loc}: unable to parse char literal: {line}")
                    self.next = Token(TokType.OTHER, line[:4], loc)
                    line = line[4:]
                    break

                # Otherwise lifetime

            # Strings
            # TODO: byte strings: b"..."
            # TODO: raw strings
            # TODO: Unicode escapes

            if line[0] == '"':
                text = ""
                start_loc = Location(loc.filename, loc.line)
                i = 1
                while True:
                    if i >= len(line):
                        self.pos += 1
                        line = self.lines[self.pos]
                        loc.line += 1
                        text += line
                        i = 0
                        continue

                    if line[i] == "\\":
                        if i == len(line) - 1:
                            self.pos += 1
                            line = self.lines[self.pos]
                            loc.line += 1
                            text += line
                            i = 0
                        elif i + 1 < len(line) and line[i + 1] == '"':
                            i += 2
                        else:
                            i += 1
                    elif line[i] != '"':
                        i += 1
                    else:
                        text += line[: i + 1]
                        break
                self.next = Token(TokType.OTHER, text, start_loc)
                line = line[i + 1 :]
                break

            # Identifiers and keywords
            # TODO: lifetimes: 'id

            if line[0].isalpha() or line[0] == "_":
                i = 1
                while i < len(line) and (line[i].isalnum() or line[i] == "_"):
                    i += 1

                id = line[:i]
                line = line[i:]

                for kw in [TokType.FN, TokType.UNSAFE, TokType.USE]:
                    if id == kw:
                        self.next = Token(kw, id, loc)
                        break
                else:
                    self.next = Token(TokType.OTHER, id, loc)

                break

            # Integers
            # TODO: floats
            # TODO: typed integers: 1i32, 0usize
            # TODO: binary and octal formats: 0b101, 0o73
            # TODO: _ separator

            if line[0].isnumeric():
                for i in range(len(line)):
                    if not line[i].isnumeric():
                        break
                else:
                    i += 1
                self.next = Token(TokType.OTHER, line[:i], loc)
                line = line[i:]
                break
            elif line.startswith("0x"):
                for i in range(2, len(line)):
                    if not line[i].isnumeric() and not line[i] in "abcdefABCDEF":
                        break
                self.next = Token(TokType.OTHER, line[:i], loc)
                line = line[i:]
                break

            # 3-char punctuation

            puncts = ["..=", "...", "<<=", ">>="]

            if any(line.startswith(p) for p in puncts):
                self.next = Token(TokType.OTHER, line[:3], loc)
                line = line[3:]
                break

            # 2-char punctuation

            puncts = [
                "#!",
                "==",
                "::",
                "||",
                "&&",
                "+=",
                "-=",
                "*=",
                "/=",
                "%=",
                "&=",
                "^=",
                "|=",
                "!=",
                "~=",
                "<=",
                ">=",
                "<<",
                ">>",
                "..",
                "->",
                "=>"
            ]

            if any(line.startswith(p) for p in puncts):
                self.next = Token(TokType.OTHER, line[:2], loc)
                line = line[2:]
                break

            # 1-char punctuation

            if line[0] == "{":
                self.next = Token(TokType.LBRACE, line[0], loc)
                line = line[1:]
                break
            elif line[0] == "}":
                self.next = Token(TokType.RBRACE, line[0], loc)
                line = line[1:]
                break
            elif line[0] == ";":
                self.next = Token(TokType.SEMI, line[0], loc)
                line = line[1:]
                break
            elif line[0] in "[]()=#,<>$:?~!&|^+-*/%@.'":
                self.next = Token(TokType.OTHER, line[0], loc)
                line = line[1:]
                break

            raise LexerError(f"{loc}: unknown token: {line}")

        if self.pos < len(self.lines):
            self.lines[self.pos] = line
        else:
            self.next = Token(TokType.EOF, "", loc)

    def peek(self):
        if self.next is None:
            self._peek_impl()
        assert self.next is not None
        return self.next

    def skip(self):
        self.next = None

    def tok(self):
        l = self.peek()
        self.skip()
        return l

    def eof(self):
        self.peek()
        return self.next.typ == TokType.EOF


def analyze(f):
    lex = Lexer(f)

    non_empty_lines = set()
    unsafe_lines = set()

    while not lex.eof():
        tok = lex.tok()

        non_empty_lines.add(tok.loc.line)

        if tok.typ != TokType.UNSAFE:
            continue

        unsafe_lines.add(tok.loc.line)

        tok = lex.peek()

        if tok.typ == TokType.LBRACE:
            # Unsafe block
            lex.skip()
        else:
            # Check for unsafe function with body

            found_fn = False
            while not lex.eof():
                tok = lex.tok()
                non_empty_lines.add(tok.loc.line)
                if tok.typ == TokType.FN:
                    found_fn = True
                    break
                elif tok.typ in (TokType.SEMI, TokType.LBRACE):
                    found_fn = False

            if not found_fn:
                # Unsafe trait or impl, not sure what to do with them
                continue

            found_lbrace = False
            while not lex.eof():
                tok = lex.tok()
                non_empty_lines.add(tok.loc.line)
                if tok.typ == TokType.LBRACE:
                    found_lbrace = True
                    break
                elif tok.typ == TokType.SEMI:
                    break

            if not found_lbrace:
                # Just declaration
                continue

        nesting = 1

        while nesting > 0:
            tok = lex.tok()
            non_empty_lines.add(tok.loc.line)
            unsafe_lines.add(tok.loc.line)
            if tok.typ == TokType.LBRACE:
                nesting += 1
            elif tok.typ == TokType.RBRACE:
                nesting -= 1
            if tok.typ == TokType.EOF:
                raise LexerError("unexpected EOF when looking for closing '}'")

    return len(non_empty_lines), len(unsafe_lines)


def main():
    def is_interesting(filename):
        return (
            filename.endswith(".rs")
            and not "test" in filename
            and not "bench" in filename
        )

    files = []
    for root in sys.argv[1:]:
        if os.path.isfile(root):
            if is_interesting(root):
                files.append(root)
        elif os.path.isdir(root):
            for d, _, ff in os.walk(root):
                for f in ff:
                    f = os.path.join(d, f)
                    if is_interesting(f):
                        files.append(f)
        else:
            sys.stderr.write(f"unexpected path: {root}")
            return 1

    total_lines = 0
    total_unsafe_lines = 0

    try:
        for f in files:
            lines, unsafe_lines = analyze(f)
            total_lines += lines
            total_unsafe_lines += unsafe_lines
    except LexerError as e:
        print(e)
        return 1

    print(f"{total_unsafe_lines} unsafe lines in {total_lines} lines")

    return 0


if __name__ == "__main__":
    sys.exit(main())
