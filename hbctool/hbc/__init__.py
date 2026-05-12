import json
from typing import BinaryIO

from hbctool.hbc.hbc59 import HBC59
from hbctool.hbc.hbc62 import HBC62
from hbctool.hbc.hbc74 import HBC74
from hbctool.hbc.hbc76 import HBC76
from hbctool.hbc.hbc84 import HBC84
from hbctool.hbc.hbc85 import HBC85
from hbctool.hbc.hbcbase import *
from hbctool.util import *

MAGIC = 2240826417119764422
INIT_HEADER = {
    "magic": ["uint", 64, 1],
    "version": ["uint", 32, 1]
}
BYTECODE_ALIGNMENT = 4

HBC = {
    85: HBC85,
    84: HBC84,
    76: HBC76,
    74: HBC74,
    62: HBC62,
    59: HBC59
}

HBCUnion = HBCBase | HBC85 | HBC76 | HBC74 | HBC62 | HBC59

def load(f: BinaryIO) -> HBCUnion:
    f = BitReader(f)  # type: ignore[assignment]
    magic = read(f, INIT_HEADER["magic"])
    version = read(f, INIT_HEADER["version"])
    f.seek(0)
    assert magic == MAGIC, f"The magic ({hex(magic)}) is invalid. (must be {hex(MAGIC)})"
    assert version in HBC, f"The HBC version ({version}) is not supported."

    return HBC[version](f)  # type: ignore[return-value]

def loado(obj):
    magic = obj["header"]["magic"]
    version = obj["header"]["version"]

    assert magic == MAGIC, f"The magic ({hex(magic)}) is invalid. (must be {hex(MAGIC)})"
    assert version in HBC, f"The HBC version ({version}) is not supported."

    hbc = HBC[version]()
    hbc.setObj(obj)
    return hbc

def dump(hbc: HBCUnion, f: BinaryIO) -> None:
    f = BitWriter(f)  # type: ignore[assignment]
    hbc.export(f)

def dumpo(hbc):
    return hbc.getObj()
