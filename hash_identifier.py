"""
Author: 

Simple hash function identifier.
"""

import argparse
from dataclasses import dataclass
from typing import Literal
from rich.table import Table
from rich.console import Console

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class HashCandidate:
    algorithm:  str
    confidence: Confidence
    reason:     str

_PREFIX_LIST: list[tuple[str, str, str]] = [
    ("$argon2id$", "Argon2id", "Modern PHC standard."),
    ("$argon2i$", "Argon2i", "PHC string, side channel resistant variant"),
    ("$2b$", "bcrypt", "..."),
    ("$1$", "MD5 crypt", "..."),
    ("$5$", "SHA-256 crypt", "..."),
    ("$6$", "SHA-512 crypt", "..."),
    ("apr1", "Apache MD5 crypt", "...")
]

_HEX_LENGTH_RULES: dict[int, list[str]] = {
    16: ["MYSQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160", "FSB-160", "HAS-160"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256", "Streebog-256", "FSB-256"],
    128: ["SHA-256", "SHA3-256", "BLAKE2b-512", "Whirlpool", "Streebog-512", "FSB-512"]
}

HEX_CHARSET: frozenset = frozenset("0123456789abcdef")
_HEX_UPPER_CHARSET: frozenset = frozenset("0123456789ABCDEF")


def _is_hex(text: str) -> bool:
    return bool(text) and all(c in HEX_CHARSET or c in _HEX_UPPER_CHARSET for c in text)

def _is_mysql5(text: str) -> bool:
    if len(text) != 41 or text[0] != "*":
        return False
    return all(c in _HEX_UPPER_CHARSET for c in text[1:])

def _is_descrypt(text: str) -> bool:
    if len(text) != 13 or text[0:2] != "./":
        return False
    return text[2:].isalnum()

def identify(raw_input: str) -> list[HashCandidate]:
    # sanity check
    text = raw_input.strip()
    if not text:
        return []
    
    # go through prefix table. iterate -> use startswith. high
    for tup in _PREFIX_LIST:
        if text.startswith(tup[0]):
            return HashCandidate(tup[1], "high", tup[2])
    
    # call helper functions shape hints is_mysql5 and is_descrypt. high/medium
    if _is_mysql5(text):
        return [HashCandidate("MYSQL5", "high", "Matching MYSQL5 structure. *[40 upper hex chars]")]
    if _is_descrypt(text):
        return [HashCandidate("DES-crypt", "high", "Matching DES-crypt structure. ./[13 hex chars]")]
    if "::" in text:
        return [HashCandidate("NetNTLM", "medium", "Matching colon structure `::`.")]

    # pure hex? look up length. medium/low, as returns a list
    if _is_hex(text):
        length = len(text)
        if _HEX_LENGTH_RULES.get(length):
            out = []
            out.append(HashCandidate(_HEX_LENGTH_RULES[length][0], "medium", f"{length} hex chars - most likely"))
            for entry in _HEX_LENGTH_RULES[length]:
                out.append[HashCandidate(entry, "low", f"{length} hex chars - also possible")]
            return _HEX_LENGTH_RULES[length]

    # phc fallback, prefix something like $xxx$... low, generic hash. More emphasis on this
    # initial version. brute force check
    if text[0] == "$":
        for i, char in enumerate(text[1::]):
            if char == "$":
                return [HashCandidate(text[1:i + 1], "low", "Generic PHC prefix found.")]

    # other shape hints? JWT: "eyJ", base64? low, return "not a hash"
    if text.startswith("eyJ"): # JWT support for now
        return [HashCandidate("JWT", "low", "JSON Web Token. Not a hash")]
    
    print("Hash could not be identified")
    return [] # nothing found


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(id="hashid", description="Hash arg parser")
    parser.add_argument("hash", help="Add hash after")
    parser.add_argument("-n", "--top", help="Top n results")

    return parser


def _render_table(raw_input: any, candidates: list[HashCandidate], console: Console) -> None:
    table = Table(title=f"top-N candidates for {raw_input}")

    table.add_column("Algorithm", justify="center")
    table.add_column("Reason", no_wrap=True)
    table.add_column("Confidence")

    for entry in candidates:
        colour = None
        # should be enforced as one of these
        if entry.confidence == "high":
            colour = "green"
        elif entry.confidence == "medium":
            colour = "yellow"
        elif entry.confidence == "low":
            colour = "red"

        table.add_row(entry.algorithm, entry.reason, entry.confidence, style=colour)

    console.print(table)

# def main() -> None:
#    pass

# if __name__ == "__main__":
#     sys.exit(main())

test = frozenset("01234")
if "0" in test:
    print("true")