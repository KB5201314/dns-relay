# dns-relay

A simple dns relay implementation based on `libuv`. Contains a cache that follows the TTL mechanism. And allows to block specific domain name resolution requests according to the configuration.

## build

- generate cmake cache

```sh
cmake .
```

- build

```sh
cmake --build .
```

## usage

```plaintext
usage: dns_relay [-d | -dd] [dns_server_ipaddr] [blocked_domains_filename]
```

