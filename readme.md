# CSOCKS

> [!WARNING]
> This is a learning project, and is not suited for real-life use.

SOCKS5/4a/4 server implementation.

I aim for the implementation to be fully compliant, but the `GSSAPI` stuff may prevent that from happening.

Heap is for loosers btw. Real programmers work on registers. /s

## Building

`POSIX SYSTEM IS REQUIRED`

Just use provided makefile

```bash
make clean all
```

There are also some configuration options in [config.def.h](config.def.h) file. You may customize them, by copying this file to `config.h` file, and editing the options. If `config.h` file is not created before the first build, it will be automatically created by the build system.

## Usage

`csocks` is a single executable, that is supposed to be run from the terminal. Just running the executable will work, but there are also flags you can use to customize the behavior of the progam:

- `-h` - display usage.
- `-n <port>` - set port to listen on. `1080` by default.
- `-a <path>` - set auth file path (see [Auth File](#Auth-File) section).
- `-l <path>` - set log file path. `stderr` by default.
- `-d` - run in daemon mode.

`csocks` will allways bind to `INADDR_ANY`.

## Auth File

User may provide path to `auth file` - a csv database containing usernames and passwords combinations permitted to use the `USERNAME/PASSWORD` authentication method, in format:

```csv
username1;password1<\n>
username2;password2<\n>
```

No rows are ignored.

## License

`csocks` is licensed under the [UNLICENSE](UNLICENSE) or [MIT-0](LICENSE); you may choose the one you prefer.
