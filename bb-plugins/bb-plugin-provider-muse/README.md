# Muse Code provider for BB

Runs Meta's Muse Code agent in BB threads. Vendored from
[braedonsaunders/bb-plugin-provider-muse](https://github.com/braedonsaunders/bb-plugin-provider-muse) at `d6b808d` (v0.16.1).

## Install

```sh
npm install
bb plugin install "$PWD" --yes
```

Sign in on the host with `muse login`. Backend changes need `npm run build && bb plugin reload provider-muse`.

## Proxy

Meta serves no models to some datacenter IPs. Set `BB_MUSE_HTTPS_PROXY` in the bb daemon's environment and every Muse child routes through it as `HTTPS_PROXY` (loopback excluded). Muse only honors `http://` proxies, so put an HTTP front on an SSH SOCKS tunnel:

```sh
ssh -N -D 127.0.0.1:1080 user@other-host
uvx --python 3.12 pproxy -l http://127.0.0.1:8888 -r socks5://127.0.0.1:1080
echo 'BB_MUSE_HTTPS_PROXY=http://127.0.0.1:8888' >> ~/.bb/bb-service.env
systemctl --user restart bb
```
