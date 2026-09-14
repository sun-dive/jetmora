# Provenance

Each row is a two-transaction genesis mint of the source archive, made with Phar Lap 2 on the BSV
blockchain: TX1 carries the archive as a file output whose SHA-256 the template commits; TX2 mints the
editions. Anyone can pull the archive from TX1, hash it, and match the column below. The archive is
`git ls-files` at the commit, built with fixed owner and mtime, so a rebuild from the same commit gives
the same hash.

| Date | Commit | Archive SHA-256 | TX1 | TX2 |
|------|--------|-----------------|-----|-----|
| 2026-09-14 | `448b796` | `8f3884e2a2ddfad74ce2ac4bc0c769b85a0ee45613c7d1a600b28fa28d03ce90` | `482539529bdc7d17b1818562bd85aeecdc6f54bf754d6fcae543ec1a9e4f564a` | `95d5ffb13ac8851b945042061b249b747ed0fd56840afa1766e343971f7e3111` |

<!-- append-only: one row per release mint, newest at the bottom -->

## OpenTimestamps

From 2026-09-14 each archive hash is also stamped with OpenTimestamps: the SHA-256 goes to the public
calendars, which commit it to the Bitcoin (BTC) blockchain in a Merkle tree. The proof file in
`provenance/` holds the path from the hash to that transaction. To check it:

    ots verify -d <sha256> provenance/<proof>.ots

A proof is pending until the calendars' transaction is mined; `ots upgrade` then completes it and the
file is re-committed with the block height below.

| Date | Commit | Archive SHA-256 | Proof | BTC block |
|------|--------|-----------------|-------|-----------|
| 2026-09-14 | `448b796` | `8f3884e2a2ddfad74ce2ac4bc0c769b85a0ee45613c7d1a600b28fa28d03ce90` | `provenance/jetmora-448b796.tar.gz.ots` | 966979, 966981 |

<!-- append-only: one row per stamped archive, newest at the bottom -->
