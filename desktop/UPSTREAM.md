# Upstream provenance

AccordLock Desktop is an independent distribution derived from
[Goose](https://github.com/aaif-goose/goose), licensed under Apache-2.0.

The AccordLock distribution started from this immutable upstream revision:

- Project: Goose
- Version: `v1.47.0`
- Commit: `f9c7aaccde4834810dfd13d5efa8f0d39ba28a20`
- Repository: `https://github.com/aaif-goose/goose.git`

AccordLock changes the product identity, desktop experience, authorization
flow, execution controls, audit surfaces, release process, and security
boundary. It is not endorsed by or affiliated with the Goose project or its
maintainers.

The original Apache-2.0 license and upstream attribution are preserved in
`LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.

## Version identities

The AccordLock product release is versioned at the public monorepo boundary.
For the first engineering alpha, that identity is `0.1.0-alpha.1`.

The desktop Rust workspace remains at Goose `1.47.0`, and inherited SDK or
binary-wrapper packages may retain their upstream compatibility versions.
Those values identify upstream components and package protocols; they are not
the AccordLock product version.
