# keepass-to-env

A simple utility to convert Keepass database to a dotenv file or to a child shell process

## why would you need it

Managing environment in `.env` file is not easy. It may contain credentials so you don't want store it in plain file. On the other hand, the Keepass database is a perfect place to store such information. This simple tool helps you generate the `.env` file or setting environment variables to a child shell from a Keepass database.

## install

```bash
cargo install keepass-to-env
```

## usage

```bash
kte --kdbx <path/to/kdbx/file> [--root <abc/def>] [--password <your/secret/password>] [--output <path/to/dot/env>]
```
