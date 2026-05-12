from struct import pack, unpack
from typing import BinaryIO, Generator, Literal, overload

from hbctool.hbc.hbcbase import *
from hbctool.util import *

from .parser import INVALID_LENGTH, export, parse
from .translator import assemble, disassemble

NullTag = 0
TrueTag = 1 << 4
FalseTag = 2 << 4
NumberTag = 3 << 4
LongStringTag = 4 << 4
ShortStringTag = 5 << 4
ByteStringTag = 6 << 4
IntegerTag = 7 << 4
TagMask = 0x70


# TODO: Fix this at the source
def wrapped_disassemble(bc: bytes | list[int]) -> Generator[InstructionDisassembled]:
    for instruction in disassemble(bc):
        yield InstructionDisassembled(
            instruction=instruction[0],
            arguments=[InstructionArgumentDisassembled._make(x) for x in instruction[1]],
        )


class HBC84(HBCBase):
    def __init__(self, f: BinaryIO | None = None):
        self.obj: Metadata | None = None
        if f:
            self.obj = parse(f)

    def export(self, f: BinaryIO) -> None:
        export(self.getObj(), f)

    def getObj(self) -> Metadata:
        assert self.obj, "Obj is not set."
        return self.obj

    def setObj(self, obj: Metadata) -> None:
        self.obj = obj

    def getVersion(self) -> Literal[84]:
        return 84

    def getHeader(self) -> Header:
        return self.getObj()["header"]

    def getFunctionCount(self) -> int:
        return self.getObj()["header"]["functionCount"]

    @overload
    def getFunction(self, fid: int, disasm: Literal[True]) -> FunctionDisassembled: ...

    @overload
    def getFunction(self, fid: int, disasm: Literal[False]) -> Function: ...

    def getFunction(self, fid: int, disasm: bool = True) -> FuncUnion:
        assert fid >= 0 and fid < self.getFunctionCount(), "Invalid function ID"

        functionHeader = self.getObj()["functionHeaders"][fid]
        offset = functionHeader["offset"]
        paramCount = functionHeader["paramCount"]
        registerCount = functionHeader["frameSize"]
        symbolCount = functionHeader["environmentSize"]
        bytecodeSizeInBytes = functionHeader["bytecodeSizeInBytes"]
        functionName = functionHeader["functionName"]

        instOffset = self.getObj()["instOffset"]
        start = offset - instOffset
        end = start + bytecodeSizeInBytes
        bc = self.getObj()["inst"][start:end]

        functionNameStr, _ = self.getString(functionName)

        if not disasm:
            return Function(
                functionNameStr,
                paramCount,
                registerCount,
                symbolCount,
                bc,
                functionHeader,
            )
        else:
            return FunctionDisassembled(
                functionNameStr,
                paramCount,
                registerCount,
                symbolCount,
                list(wrapped_disassemble(bc)),
                functionHeader,
            )

    def setFunction(self, fid: int, func: FuncUnion, disasm: bool = True) -> None:
        assert fid >= 0 and fid < self.getFunctionCount(), "Invalid function ID"

        functionName, paramCount, registerCount, symbolCount, insts, _ = func

        functionHeader = self.getObj()["functionHeaders"][fid]

        functionHeader["paramCount"] = paramCount
        functionHeader["frameSize"] = registerCount
        functionHeader["environmentSize"] = symbolCount

        # TODO : Make this work
        # functionHeader["functionName"] = functionName

        offset = functionHeader["offset"]
        bytecodeSizeInBytes = functionHeader["bytecodeSizeInBytes"]

        instOffset = self.getObj()["instOffset"]
        start = offset - instOffset

        bc = insts

        if disasm:
            bc = assemble(insts)

        assert (
            len(bc) <= bytecodeSizeInBytes
        ), "Overflowed instruction length is not supported yet."
        functionHeader["bytecodeSizeInBytes"] = len(bc)
        memcpy(self.getObj()["inst"], bc, start, len(bc))

    def getStringCount(self) -> int:
        return self.getObj()["header"]["stringCount"]

    def getString(self, sid: int) -> String:
        assert sid >= 0 and sid < self.getStringCount(), "Invalid string ID"

        stringTableEntry = self.getObj()["stringTableEntries"][sid]
        stringStorage = self.getObj()["stringStorage"]
        stringTableOverflowEntries = self.getObj()["stringTableOverflowEntries"]

        isUTF16 = stringTableEntry["isUTF16"]
        offset = stringTableEntry["offset"]
        length = stringTableEntry["length"]

        if length >= INVALID_LENGTH:
            stringTableOverflowEntry = stringTableOverflowEntries[offset]
            offset = stringTableOverflowEntry["offset"]
            length = stringTableOverflowEntry["length"]

        if isUTF16:
            length *= 2

        s = bytes(stringStorage[offset : offset + length])
        return String(
            s.hex() if isUTF16 else s.decode("utf-8"),
            StringMetadata(isUTF16, offset, length),
        )

    def setString(self, sid: int, val: str) -> None:
        assert sid >= 0 and sid < self.getStringCount(), "Invalid string ID"

        stringTableEntry = self.getObj()["stringTableEntries"][sid]
        stringStorage = self.getObj()["stringStorage"]
        stringTableOverflowEntries = self.getObj()["stringTableOverflowEntries"]

        isUTF16 = stringTableEntry["isUTF16"]
        offset = stringTableEntry["offset"]
        length = stringTableEntry["length"]

        if length >= INVALID_LENGTH:
            stringTableOverflowEntry = stringTableOverflowEntries[offset]
            offset = stringTableOverflowEntry["offset"]
            length = stringTableOverflowEntry["length"]

        s: list[int] | bytes
        if isUTF16:
            s = list(bytes.fromhex(val))
            l = len(s) // 2
        else:
            l = len(val)
            s = val.encode("utf-8")

        assert l <= length, "Overflowed string length is not supported yet."

        memcpy(stringStorage, s, offset, len(s))

    def _checkBufferTag(self, buf, iid):
        keyTag = buf[iid]
        if keyTag & 0x80:
            return (((keyTag & 0x0F) << 8) | (buf[iid + 1]), keyTag & TagMask)
        else:
            return (keyTag & 0x0F, keyTag & TagMask)

    def _SLPToString(self, tag, buf, iid, ind):
        start = iid + ind
        if tag == ByteStringTag:
            type = "String"
            val = buf[start]
            ind += 1
        elif tag == ShortStringTag:
            type = "String"
            val = unpack("<H", bytes(buf[start : start + 2]))[0]
            ind += 2
        elif tag == LongStringTag:
            type = "String"
            val = unpack("<L", bytes(buf[start : start + 4]))[0]
            ind += 4
        elif tag == NumberTag:
            type = "Number"
            val = unpack("<d", bytes(buf[start : start + 8]))[0]
            ind += 8
        elif tag == IntegerTag:
            type = "Integer"
            val = unpack("<L", bytes(buf[start : start + 4]))[0]
            ind += 4
        elif tag == NullTag:
            type = "Null"
            val = None
        elif tag == TrueTag:
            type = "Boolean"
            val = True
        elif tag == FalseTag:
            type = "Boolean"
            val = False
        else:
            type = "Empty"
            val = None

        return type, val, ind

    def getArrayBufferSize(self) -> int:
        return self.getObj()["header"]["arrayBufferSize"]

    def getArray(self, aid):
        assert aid >= 0 and aid < self.getArrayBufferSize(), "Invalid Array ID"
        tag = self._checkBufferTag(self.getObj()["arrayBuffer"], aid)
        ind = 2 if tag[0] > 0x0F else 1
        arr = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(
                tag[1], self.getObj()["arrayBuffer"], aid, ind
            )
            arr.append(val)

        return t, arr

    def getObjKeyBufferSize(self):
        return self.getObj()["header"]["objKeyBufferSize"]

    def getObjKey(self, kid):
        assert kid >= 0 and kid < self.getObjKeyBufferSize(), "Invalid ObjKey ID"
        tag = self._checkBufferTag(self.getObj()["objKeyBuffer"], kid)
        ind = 2 if tag[0] > 0x0F else 1
        keys = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(
                tag[1], self.getObj()["objKeyBuffer"], kid, ind
            )
            keys.append(val)

        return t, keys

    def getObjValueBufferSize(self):
        return self.getObj()["header"]["objValueBufferSize"]

    def getObjValue(self, vid):
        assert vid >= 0 and vid < self.getObjValueBufferSize(), "Invalid ObjValue ID"
        tag = self._checkBufferTag(self.getObj()["objValueBuffer"], vid)
        ind = 2 if tag[0] > 0x0F else 1
        keys = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(
                tag[1], self.getObj()["objValueBuffer"], vid, ind
            )
            keys.append(val)

        return t, keys
