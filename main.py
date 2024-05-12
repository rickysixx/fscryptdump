#!/usr/bin/env python

import os
import shutil

import cli
import fscrypt
import ioctl

from typing import List, Tuple

from proto import metadata_pb2

def _check_for_fscrypt_dir(mountpoint: str):
    if not os.path.isdir(f'{mountpoint}/.fscrypt'):
        raise ValueError(f'Mountpoint {mountpoint} does not have an .fscrypt directory')

def _ask_for_protector_to_use(policy_data: metadata_pb2.PolicyData, mountpoint: str) -> Tuple[metadata_pb2.ProtectorData, metadata_pb2.WrappedKeyData]:
    protectors = fscrypt.get_protectors(policy_data, mountpoint)

    print(f'Policy {policy_data.key_descriptor} has more than 1 protector.')
    print('Choose which one to use:')
    
    for i, protector in enumerate(protectors):
        print(f'{i + 1}: {protector.protector_descriptor} (type {protector.source})')
    
    choice = int(input(f'Enter your selection (1-{len(protectors)}): '))

    if choice < 1 or choice > len(protectors):
        raise ValueError('Invalid choice!')
    
    return (protectors[choice - 1], policy_data.wrapped_policy_keys[choice - 1].wrapped_key)

def _get_protector_from_policy(policy_data: metadata_pb2.PolicyData, mountpoint: str) -> Tuple[metadata_pb2.ProtectorData, metadata_pb2.WrappedKeyData]:
    if len(policy_data.wrapped_policy_keys) == 1:
        return (fscrypt.parse_protector_data(mountpoint, policy_data.wrapped_policy_keys[0].protector_descriptor), policy_data.wrapped_policy_keys[0].wrapped_key)
    else:
        return _ask_for_protector_to_use(policy_data, mountpoint)

def main():
    args = cli.parse_args()

    _check_for_fscrypt_dir(args.mountpoint)

    for dir_relative_path in args.dirs:
        dir_absolute_path = f'{args.mountpoint}/{dir_relative_path}'

        if not os.path.isdir(dir_absolute_path):
            raise ValueError(f"Directory {dir_absolute_path} does not exist or it's not a directory")
        
        policy_descriptor = ioctl.get_policy_key_descriptor(dir_absolute_path)
        policy_data = fscrypt.parse_policy_data(args.mountpoint, policy_descriptor.hex())
        protector_data, wrapped_policy_key = _get_protector_from_policy(policy_data, args.mountpoint)
        password = input(f'Enter key to unlock protector {protector_data.protector_descriptor}: ')
        wrapping_key = fscrypt.hash_password(password, protector_data)
        protector_key = fscrypt.unwrap_key(protector_data.wrapped_key, wrapping_key)
        policy_key = fscrypt.unwrap_key(wrapped_policy_key, protector_key)
        res = ioctl.add_encryption_key(policy_key, bytes.fromhex(policy_data.key_descriptor), args.mountpoint)

        print(f'Directory {dir_relative_path} has been unlocked')
        print(f'Copying content of {dir_relative_path} to {args.output_dir}...')

        shutil.copytree(dir_absolute_path, f'{args.output_dir}/{dir_relative_path}')

        print(f'Finished copying of {dir_relative_path}')
        print(f'Locking {dir_relative_path}...')

        res = ioctl.remove_encryption_key(bytes.fromhex(policy_data.key_descriptor), args.mountpoint)

        print(f'{dir_relative_path} locked.')

if __name__ == '__main__':
    main()