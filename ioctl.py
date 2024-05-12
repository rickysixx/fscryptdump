import fcntl
import os
import struct

FS_IOC_ADD_ENCRYPTION_KEY = 0xc0506617
FS_IOC_REMOVE_ENCRYPTION_KEY = 0xc0406618
FS_IOC_GET_ENCRYPTION_POLICY_EX = 0xc0096616

FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER = 2

FSCRYPT_KEY_IDENTIFIER_SIZE = 16

def pack_fscrypt_key_specifier(key_identifier: bytes) -> bytes:
    return struct.pack(
        '=II32s',
        FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER,
        0,
        key_identifier
    )

def add_encryption_key(policy_key: bytes, key_identifier: bytes, fs_root_path: str) -> bytes:
    fscrypt_key_specifier = pack_fscrypt_key_specifier(key_identifier)
    fscrypt_add_key_arg = struct.pack(
        f'{len(fscrypt_key_specifier)}sII8I{len(policy_key)}s',
        fscrypt_key_specifier,
        len(policy_key),
        0,
        0, 0, 0, 0, 0, 0, 0, 0,
        policy_key
    )
    fd = os.open(fs_root_path, os.O_RDONLY)
    res = fcntl.ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, fscrypt_add_key_arg)
    os.close(fd)

    return res

def remove_encryption_key(key_identifier: bytes, fs_root_path: str) -> bytes:
    fscrypt_key_specifier = pack_fscrypt_key_specifier(key_identifier)
    fscrypt_remove_key_arg = struct.pack(
        f'{len(fscrypt_key_specifier)}sI5I',
        fscrypt_key_specifier,
        0,
        0, 0, 0, 0, 0
    )
    fd = os.open(fs_root_path, os.O_RDONLY)
    res = fcntl.ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, fscrypt_remove_key_arg)
    os.close(fd)

    return res

def get_policy_key_descriptor(path: str) -> bytes:
    policy_size = 24
    fscrypt_get_policy_ex_arg = struct.pack(
        f'=Q{policy_size}s',
        policy_size,
        bytes([0] * policy_size)
    )

    fd = os.open(path, os.O_RDONLY)
    res = fcntl.ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, fscrypt_get_policy_ex_arg)
    os.close(fd)

    res = struct.unpack(
        f'=QBBBBB3B{FSCRYPT_KEY_IDENTIFIER_SIZE}B',
        res
    )
    policy_key_descriptor = bytes(res[-FSCRYPT_KEY_IDENTIFIER_SIZE:])

    return policy_key_descriptor