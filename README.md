# fscryptdump

A simple Python script that allows to quickly dump files encrypted using [fscrypt](https://github.com/google/fscrypt) from an external hard drive.

# Install

1. install [pipenv](https://pipenv.pypa.io/en/latest/installation.html);
2. clone the project;
3. run `pipenv install` in the project's root directory

# Usage

## 1. generate Python code for protobufs

1. install the [protoc compiler](https://github.com/protocolbuffers/protobuf?tab=readme-ov-file#protobuf-compiler-installation);
2. from the project's root directory, run
```
protoc -I=proto --python_out=pyi_out:proto proto/metadata.proto
```

## 2. dump files

Execute the `main.py` script (run `./main.py -h` for usage).

You will need root permissions to execute the dump if files on the external hard drive are not owned by your user.

# License

This project is licensed under the [MIT license](https://spdx.org/licenses/MIT.html).

Exception is for `proto/metadata.proto`, which is licensed under [Apache License 2.0](https://spdx.org/licenses/Apache-2.0.html). See [google/fscrypt](https://github.com/google/fscrypt) for more information.