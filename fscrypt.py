import io

from base64 import b64decode
from typing import List

from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util import Counter
from proto import metadata_pb2

INTERNAL_KEY_LENGTH = 32
IV_LENGTH = 16

def open_protector_file(mountpoint: str, descriptor: str) -> io.TextIOBase:
    try:
        return open(f'{mountpoint}/.fscrypt/protectors/{descriptor}', 'rb')
    except FileNotFoundError:
        return open(f'/.fscrypt/protectors/{descriptor}', 'rb')

def parse_policy_data(mountpoint: str, descriptor: str) -> metadata_pb2.PolicyData:
    with open(f'{mountpoint}/.fscrypt/policies/{descriptor}', 'rb') as f:
        policy_data = metadata_pb2.PolicyData()
        policy_data.ParseFromString(f.read())

        return policy_data

def parse_protector_data(mountpoint: str, descriptor: str) -> metadata_pb2.ProtectorData:
    with open_protector_file(mountpoint, descriptor) as f:
        protector_data = metadata_pb2.ProtectorData()
        protector_data.ParseFromString(f.read())

        return protector_data

def hash_password(password: str, protector_data: metadata_pb2.ProtectorData) -> bytes:
    if not protector_data.salt:
        raise ValueError(f'This protector does not use an hashed password: {protector_data}')
    
    hasher = PasswordHasher(
        time_cost=protector_data.costs.time,
        memory_cost=protector_data.costs.memory,
        parallelism=protector_data.costs.parallelism,
        hash_len=INTERNAL_KEY_LENGTH
    )

    pw_hash = b64decode(hasher.hash(password, salt=protector_data.salt)[57:] + '==')

    return pw_hash

def stretch_key(key: bytes) -> (bytes, bytes):
    enc_key, auth_key = HKDF(
        key,
        key_len=INTERNAL_KEY_LENGTH,
        salt=None,
        hashmod=SHA256,
        num_keys=2
    )

    return (enc_key, auth_key)

def unwrap_key(wrapped_key: metadata_pb2.WrappedKeyData, wrapping_key: bytes) -> bytes:
    enc_key, auth_key = stretch_key(wrapping_key)
    mac = HMAC.new(auth_key, digestmod=SHA256)

    mac.update(wrapped_key.IV)
    mac.update(wrapped_key.encrypted_key)
    mac.verify(wrapped_key.hmac)

    counter = Counter.new(nbits=IV_LENGTH * 8, initial_value=int.from_bytes(wrapped_key.IV, byteorder='big', signed=False))
    cipher = AES.new(enc_key, AES.MODE_CTR, counter=counter)
    secret_key = cipher.decrypt(wrapped_key.encrypted_key)

    return secret_key

def get_protectors(policy_data: metadata_pb2.PolicyData, mountpoint: str) -> List[metadata_pb2.ProtectorData]:
    protectors: List[metadata_pb2.ProtectorData] = []

    for protector_descriptor in map(lambda wrapped_policy_key: wrapped_policy_key.protector_descriptor, policy_data.wrapped_policy_keys):
        protectors.append(parse_protector_data(mountpoint, protector_descriptor))
    
    return protectors