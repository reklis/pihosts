# pihosts

A CLI tool to manage Pi-hole DNS hosts via the v6 API.

## Installation

Download the latest binary from [Releases](https://github.com/reklis/pihosts/releases) or build from source:

```bash
cargo install --path .
```

## Usage

### Login

Save your Pi-hole server URL and password to the config file:

```bash
pihosts login https://pihole.example.com 'yourpassword'
```

This stores credentials in `~/.config/pihosts/config.json` and caches the session in `~/.config/pihosts/sid`.

### List hosts

```bash
pihosts list
```

With options:

```bash
pihosts -c list        # colored output
pihosts -t list        # table format
pihosts -ct list       # colored table
pihosts -j list        # JSON output
```

### Add a host

```bash
pihosts add 192.168.1.100 myhost.example.com
```

### Remove a host

```bash
pihosts remove 192.168.1.100 myhost.example.com
```

## Configuration

Credentials can be provided via:

1. Config file (created by `pihosts login`)
2. Environment variables: `PIHOLE_URL` and `PIHOLE_PASSWORD`
3. Command line flags: `-s/--server` and `-p/--password`

Priority: CLI flags > environment variables > config file

## License

GPL-3.0
