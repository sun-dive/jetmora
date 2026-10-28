' © 2026 sun-dive. Apache License 2.0.
'
' The covenant of jetmora's own code thread, in jetForth BASIC, compiled by compileCovenant (basic/basic-jf.mjs).
' Each release is one tick, signed by the release key, carrying the code bundle and the engine revision it
' implements. The successor's state keeps the bundle's SHA-256 and that revision: the tip names the latest
' release, and the bytes of each release are in the tick that made it.
' The file holds no key and no owner hash: the genesis state (owner, rev, code) is given when the thread is made.
VERSION JF 3
DIM owner$20         ' who may release: the hash of the release key
DIM rev%2            ' the engine revision this release implements
DIM code$32          ' SHA-256 of the release's code
INPUT bundle$, r%    ' carried by the tick: the code itself, and its revision
code = SHA256(bundle)
rev = r
