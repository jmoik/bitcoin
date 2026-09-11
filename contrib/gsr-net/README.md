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

Connect with this branch's binaries:

```sh
bitcoind -signet \
  -signetchallenge=00148f972ab78125ec8f1cceff9d82c7251c9e56ae84 \
  -vbparams=script_restoration:-1:0 \
  -addnode=65.21.21.199:38333
```

The RPC service is intentionally bound to loopback. Do not expose port 38332
to the public internet. Public transaction submission will be provided by the
explorer/API layer.
