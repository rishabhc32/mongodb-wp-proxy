# mongodb-oidc-proxy

OIDC-aware logging MongoDB wire protocol proxy.

**Transparent proxy mode (default):**
```shell
mongodb-wp-proxy [--ndjson] <remotehost:remoteport> <[localhost:]localport>
```

**OIDC proxy mode:**
```shell
mongodb-wp-proxy [--ndjson] [--tag <value>]... --oidc-mode --issuer <url> --client-id <id> --connection-string <uri> [--jwks-uri <url>] [--audience <aud>] <[localhost:]localport>
```

The `--tag` option can be specified multiple times to add multiple tags to log entries:
```shell
mongodb-wp-proxy --tag prod --tag us-east-1 --oidc-mode ...
```

## LICENSE

Apache-2.0
