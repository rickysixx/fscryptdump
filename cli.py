import argparse

from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class CliArgs:
    mountpoint: str
    dirs: List[str]
    output_dir: str

def _setup_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='fscrypt dumper',
        description='Dump directories encrypted with fscrypt',
    )

    parser.add_argument(
        'mountpoint',
        help='The mount point to analyze for fscrypt encrypted files'
    )

    parser.add_argument(
        '-d', '--dir',
        help='A list of directory paths (relative to the mountpoint), encrypted using fscrypt, to dump',
        nargs='+',
    )

    parser.add_argument(
        '-o', '--output-dir',
        help='Directory path where to store the decrypted files',
        required=True
    )

    return parser

def parse_args() -> CliArgs:
    parser = _setup_argparser()
    args = parser.parse_args()

    return CliArgs(
        mountpoint=args.mountpoint,
        dirs=args.dir,
        output_dir=args.output_dir,
    )
