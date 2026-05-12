from abc import ABC, abstractmethod
from typing import BinaryIO, Literal, NamedTuple, TypedDict, overload


class Header(TypedDict):
    magic: int
    version: int
    sourceHash: list[int]
    fileLength: int
    globalCodeIndex: int
    functionCount: int
    stringKindCount: int
    identifierCount: int
    stringCount: int
    overflowStringCount: int
    stringStorageSize: int
    regExpCount: int
    regExpStorageSize: int
    arrayBufferSize: int
    objKeyBufferSize: int
    objValueBufferSize: int
    segmentID: int
    cjsModuleCount: int
    functionSourceCount: int
    debugInfoOffset: int
    option: int
    padding: list[int]


class FunctionHeader(TypedDict):
    offset: int
    paramCount: int
    bytecodeSizeInBytes: int
    functionName: int
    infoOffset: int
    frameSize: int
    environmentSize: int
    highestReadCacheIndex: int
    highestWriteCacheIndex: int
    flags: int


class StringTableEntry(TypedDict):
    isUTF16: int
    offset: int
    length: int


class StringTableOverflowEntry(TypedDict):
    offset: int
    length: int


class RegExpTableEntry(TypedDict):
    offset: int
    length: int


class Metadata(TypedDict):
    header: Header
    functionHeaders: list[FunctionHeader]
    stringKinds: list[int]
    identifierHashes: list[int]
    stringTableEntries: list[StringTableEntry]
    stringTableOverflowEntries: list[StringTableOverflowEntry]
    stringStorage: list[int]
    arrayBuffer: list[int]
    objKeyBuffer: list[int]
    objValueBuffer: list[int]
    regExpTable: list[RegExpTableEntry]
    regExpStorage: list[int]
    cjsModuleTable: list
    instOffset: int
    inst: list[int]


class Function(NamedTuple):
    name: str
    param_count: int
    register_count: int
    symbol_count: int
    instructions: list[int]
    header: FunctionHeader


class InstructionArgumentDisassembled(NamedTuple):
    arg_type: str
    is_string: bool
    arg_value: int


class InstructionDisassembled(NamedTuple):
    instruction: str
    arguments: list[InstructionArgumentDisassembled]


class FunctionDisassembled(NamedTuple):
    name: str
    param_count: int
    register_count: int
    symbol_count: int
    instructions: list[InstructionDisassembled]
    header: FunctionHeader


class StringMetadata(NamedTuple):
    is_utf16: int
    offset: int
    length: int


class String(NamedTuple):
    val: str
    metadata: StringMetadata


FuncUnion = Function | FunctionDisassembled


class HBCBase(ABC):
    @abstractmethod
    def __init__(self, f: BinaryIO | None = None): ...

    @abstractmethod
    def export(self, f: BinaryIO) -> None: ...

    @abstractmethod
    def getObj(self) -> Metadata: ...

    @abstractmethod
    def setObj(self, obj: Metadata) -> None: ...

    @abstractmethod
    def getVersion(self) -> int: ...

    @abstractmethod
    def getHeader(self) -> Header: ...

    @abstractmethod
    def getFunctionCount(self) -> int: ...

    @abstractmethod
    def getFunction(self, fid: int, disasm: bool = True) -> FuncUnion: ...

    @abstractmethod
    def getBareFunction(self, fid: int) -> Function: ...

    @abstractmethod
    def getDisassembledFunction(self, fid: int) -> FunctionDisassembled: ...

    # TODO: Remove this disasm and rely on the func type
    @abstractmethod
    def setFunction(
        self,
        fid: int,
        func: FuncUnion,
        disasm: bool = True,
    ) -> None: ...

    @abstractmethod
    def getStringCount(self) -> int: ...

    @abstractmethod
    def getString(self, sid: int) -> String: ...

    @abstractmethod
    def setString(self, sid: int, val: str) -> None: ...

    @abstractmethod
    def getArrayBufferSize(self) -> int: ...
