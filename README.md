# keepass-to-env

A simple utility to convert Keepass datbase to a dotenv file or to a child shell process

# why would you need it

Managing environment in `.env` file is not easy. It may contain creadentials so you don't want store it in plain file. On the other hand, the Keepass database is a perfect place to store such information. This simple tool helps you generate the `.env` file or setting environment variables to a child shell from a Keepass database.

# install

```
cargo install keepass-to-env
```

# usage

```
keepass-to-env --kdbx <path/to/kdbx/file> --password <your/secret/password> [--output <path/to/dot/env>]
```
