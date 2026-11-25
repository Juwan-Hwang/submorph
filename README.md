# submorph

A fast, lossless subscription converter for proxy clients, written in Rust.

submorph reads a proxy subscription and writes it out for another client,
keeping your own proxy groups, rules and DNS instead of swapping them for a
template. Anything it cannot carry over is reported item by item, never
dropped silently. It runs entirely offline: no subscription is ever sent to a
remote service.

> Status: early development (phase one, not released). See
> [docs/progress.md](docs/progress.md) for what works today and what is next.

## Formats

Input (detected automatically):

- Clash / Mihomo YAML and JSON
- sing-box JSON
- share links: `ss`, `ssr`, `vmess`, `vless`, `trojan`, `hysteria`,
  `hysteria2`/`hy2`, `tuic`, `anytls`, `wireguard`, `socks`, `http(s)`
- Base64 subscriptions (nested up to three levels)

Output:

- mihomo (Clash.Meta) YAML
- sing-box JSON in the 1.12+ format: rules use `rule_set`, never the removed
  `geoip` / `geosite` fields, and DNS uses the new server format

More targets (Surge, Stash, Loon, Quantumult X, Shadowrocket, then Surfboard,
Egern, V2Ray) are planned behind the same `Target` interface.

## Usage

```sh
cargo build --release
./target/release/submorph -t sing-box config.yaml -o config.json
./target/release/submorph -t mihomo subscription.txt > config.yaml
```

```
usage: submorph -t <mihomo|sing-box> [options] [INPUT]

  -t, --target ID          mihomo or sing-box
  -o, --output FILE        write the config to FILE instead of stdout
      --provider NAME=FILE inline a rule provider's list (repeatable)
      --no-defaults        do not add a group, final rule or port to bare node lists
      --diagnostics FMT    text (default, to stderr), json (to stderr) or none
      --strict             exit with status 2 when any item was dropped
```

As a library:

```rust
let out = submorph::convert(input, "sing-box", &submorph::ConvertOptions::default())?;
println!("{}", out.output);
for d in &out.diagnostics.items {
    eprintln!("{d}");
}
```

## Scope

submorph only converts subscription formats. Scripts, overrides and
subscription management are out of scope.

## Documentation

- [Requirements](docs/requirements.md)
- [Design](docs/design.md)
- [Benchmark](docs/benchmark.md)
- [Progress and next steps](docs/progress.md)
- [Research on existing converters](docs/research.html)

## License

MIT. submorph is written from the public format documentation of mihomo and
sing-box; it contains no code from GPL or AGPL converters.
