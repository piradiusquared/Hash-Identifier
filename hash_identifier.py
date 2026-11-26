"""
Author: 

Simple hash function identifier.
"""

import argparse
from dataclasses import dataclass
from typing import List, Literal, Optional
from rich.table import Table
from rich.console import Console

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class HashCandidate:
    algorithm:  str
    confidence: Confidence
    reason:     str

_PREFIX_LIST = [
    ("$argon2id$", "Argon2id", "..."),
    ("$2b$", "bcrypt", "..."),
    ("$1$", "MD5 crypt", "..."),
    ("$5$", "SHA-256 crypt", "..."),
    ("$6$", "SHA-512 crypt", "..."),
    ("apr1", "Apache MD5 crypt", "...")
]

_HEX_LENGTH_RULES = {
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160", "FSB-160", "HAS-160"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256", "Streebog-256", "FSB-256"],
    128: ["SHA-256", "SHA3-256", "BLAKE2b-512", "Whirlpool", "Streebog-512", "FSB-512"]
}

HEX_CHARSET = frozenset(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"])
_HEX_UPPER_CHARSET = frozenset(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"])


def _is_hex(text: str) -> bool:
    for char in text:
        if char not in HEX_CHARSET or char not in _HEX_UPPER_CHARSET:
            return False
    return True

def _is_mysql5(text: str) -> bool:
    if len(text) != 41 or text[0] != "*":
        return False
    for char in text[1::]:
        if char not in _HEX_UPPER_CHARSET:
            return False
    for i, char in enumerate(text):
        if i == 0 and char != "*":
            return False
        if i > 0 and not char.isalnum():
            return False
        if i > 40:
            return False
    return True

def _is_descrypt(text: str) -> bool:
    if len(text) != 13 or text[0:2] != "./":
        return False
    return text[2::].isalnum()

def identify(text: str) -> Optional[List[HashCandidate]]:

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
    

    # other shape hints? JWT: "eyJ", base64? low, return "not a hash"
    if text.startswith("eyJ"): # JWT support for now
        return [HashCandidate("JWT", "medium", "JSON Web Token. Not a hash")]
    
    print("Hash could not be identified")
    return [] # nothing found


# def main() -> None:
#    pass

# if __name__ == "__main__":
#     sys.exit(main())