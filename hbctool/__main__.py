import argparse
import logging
from pathlib import Path

from hbctool import hasm, hbc

from . import __description__, __version__

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

prog = "hbctool"
epilog = """Usage:
    hbctool disasm HBC_FILE HASM_PATH
    hbctool asm HASM_PATH HBC_FILE
    hbctool --help
    hbctool --version

Args:
    HBC_FILE            Target HBC file
    HASM_PATH           Target HASM directory path

Examples:
    hbctool disasm index.android.bundle test_hasm
    hbctool asm test_hasm index.android.bundle
"""


def disasm(hbcfile, hasmpath):
    logger.info("[*] Disassemble '%s' to '%s' path", hbcfile, hasmpath)
    f = open(hbcfile, "rb")
    hbco = hbc.load(f)
    f.close()

    header = hbco.getHeader()
    sourceHash = bytes(header["sourceHash"]).hex()
    version = header["version"]
    logger.info(
        "[*] Hermes Bytecode [ Source Hash: %s, HBC Version: %s ]", sourceHash, version
    )

    hasm.dump(hbco, hasmpath)
    logger.info(f"[*] Done")


def asm(hasmpath, hbcfile):
    logger.info("[*] Assemble '%s' to '%s' path", hasmpath, hbcfile)
    hbco = hasm.load(hasmpath)

    header = hbco.getHeader()
    sourceHash = bytes(header["sourceHash"]).hex()
    version = header["version"]
    logger.info(
        "[*] Hermes Bytecode [ Source Hash: %s, HBC Version: %s ]", sourceHash, version
    )

    f = open(hbcfile, "wb")
    hbc.dump(hbco, f)
    f.close()
    logger.info(f"[*] Done")


def path_exists(source: str) -> Path:
    p = Path(source)
    if not p.exists():
        raise argparse.ArgumentTypeError(f"Path {source} doesn't exist")
    return p


def main():
    parser = argparse.ArgumentParser(
        prog=prog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__description__,
        epilog=epilog,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    operations = parser.add_subparsers(title="operations")

    hbc_file_arg = {"type": Path, "help": "Target HBC file", "metavar": "HBC_FILE"}
    hasm_path_arg = {
        "type": Path,
        "help": "Target HASM directory path",
        "metavar": "HASM_PATH",
    }

    parser_disasm = operations.add_parser("disasm", help="Disassemble Hermes Bytecode")
    parser_disasm.add_argument("hbcfile", **(hbc_file_arg | {"type": path_exists}))
    parser_disasm.add_argument("hasm_path", **hasm_path_arg)
    parser_disasm.set_defaults(func=lambda args: disasm(args.hbcfile, args.hasm_path))

    parser_asm = operations.add_parser("asm", help="Assemble Hermes Bytecode")
    parser_asm.add_argument("hasm_path", **(hasm_path_arg | {"type": path_exists}))
    parser_asm.add_argument("hbcfile", **hbc_file_arg)
    parser_asm.set_defaults(func=lambda args: asm(args.hasm_path, args.hbcfile))

    args = parser.parse_args()
    args.func(args)


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    main()


if __name__ == "__main__":
    main()
