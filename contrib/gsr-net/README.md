# gsr-net

`gsr-net` is a disposable public custom Signet for experimenting with GSR and
Tapscript v2. It targets 30-second blocks and activates the
`script_restoration` deployment from genesis.

## Public network parameters

- IPv4 seed: `65.21.21.199:38333`
- Signet challenge: `00148f972ab78125ec8f1cceff9d82c7251c9e56ae84`
- Signet message magic: `3777fcb0`
- Target block spacing: 30 seconds
- Initial target nBits: `1e0377ae`
- GSR deployment: always active (`script_restoration:-1:0`)

## Public explorer

- Explorer: `https://gsr-net.65-21-21-199.sslip.io`
- Faucet: `https://gsr-net.65-21-21-199.sslip.io/faucet/`
- Playground: `https://gsr-net.65-21-21-199.sslip.io/playground/`
- REST API: `https://gsr-net.65-21-21-199.sslip.io/api/`
- Broadcast a raw transaction: `POST /api/tx`

The temporary `sslip.io` hostname resolves directly to the public server IP and
lets Caddy provision HTTPS without requiring a purchased domain.

The faucet sends 1 test BTC per address and client IP per hour. The playground
creates disposable server-managed wallets, sends ordinary payments, and can
build a real leaf-version-`0xc2` transaction that executes `OP_BYTEREV`. Its
wallets are custodial test accounts and must never be used for valuable keys or
coins.

Connect with this branch's binaries:

```sh
bitcoind -signet \
  -signetchallenge=00148f972ab78125ec8f1cceff9d82c7251c9e56ae84 \
  -vbparams=script_restoration:-1:0 \
  -addnode=65.21.21.199:38333
```

The RPC service is intentionally unavailable on the public internet. It is
bound to loopback and the isolated `172.29.0.0/24` explorer bridge. Public
transaction submission is provided by the explorer/API layer instead.
