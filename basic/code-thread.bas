' © 2026 sun-dive. Apache License 2.0.
'
' The covenant of jetmora's own code thread, in jetForth BASIC, compiled by compileCovenant (basic/basic-jf.mjs).
' A release is a thread of its own: each tick, signed by the release key, carries one part of the code archive and
' the engine revision; the successor keeps that part's SHA-256 and the revision.
' The file holds no key and no owner hash: the genesis state (owner, rev, code) is given when the thread is made.
VERSION JF 3
DIM owner$20         ' who may release: the hash of the release key
DIM rev%2            ' the engine revision of this part's code
DIM code$32          ' SHA-256 of this tick's part of the archive
INPUT bundle$, r%    ' carried by the tick: one part of the archive, and its revision
code = SHA256(bundle)
rev = r
