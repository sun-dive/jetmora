REM  The 7 Sept counter (server/verify-wired.php), written in BASIC.
REM  A tick is accepted when its one successor carries this same script, and the value plus one.
VERSION JF 3
REM  The preimage ends with: value 8, nSequence 4, hashOutputs 32, locktime 4, sighash type 4.
n = SIZE(preimage)
head, tail = SPLIT(preimage, n - 52)
value, tail = SPLIT(tail, 8)
nseq, tail = SPLIT(tail, 4)
hashout, tail = SPLIT(tail, 32)
REM  From byte 104: the scriptCode with its length in front, as an output carries it.
skip, code = SPLIT(head, 104)
VERIFY SAMEBYTES(HASH256(CAT(NUM2BIN(BIN2NUM(value) + 1, 8), code)), hashout)
