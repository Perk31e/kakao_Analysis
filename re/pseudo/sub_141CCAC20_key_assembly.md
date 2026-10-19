# `sub_141CCAC20` — per-DB raw key assembler (annotated)

Source: live disassembly of the unpacked function in a running `KakaoTalk.exe`
(image base `0x140000000`), read externally with capstone 5.0.7 over
`ReadProcessMemory` (2026-10-19). Addresses are stable across runs (fixed base, no ASLR).

Signature (observed): `std::string* sub_141CCAC20(void* ctx /*rcx*/, std::string* out /*rdx=r12*/, std::string* dbNameRel /*r8=rbx*/)`
Returns `out` = the SQLCipher key spec string `"x'<64 hex>'"` for the given DB.

## Control flow

```
lock(ctx->srw @ *(ctx))                         ; sub_142374224 (reentrant SRW acquire)
sub_141CC8B40(&loc, dbNameRel, ctx+8)           ; normalize path -> base-relative "chat_data\\<name>.edb"
h = FNV1a64(loc)                                ; off=0xCBF29CE484222325, prime=0x100000001B3
bucket = ctx->buckets[(h & ctx->mask)*2 + 1]    ; ctx+0x158 buckets, ctx+0x170 mask(=0x3F)
node  = walk list from bucket, strcmp key == loc  ; node found -> r14
if (!node || node == end) -> write empty out, unlock, return

; ---- key derivation (node found) ----
esi = (*(ctx+0xD8))->vtbl[0x10]()               ; int: iteration/mode selector
rA  = sub_141CCC710(ctx, &outPre /*rsp+0x50*/)  ; build KDF pre-input from ctx secrets
                                                ; (rbx = ctx+0x68 = SECRET_A kept live)
; stack args for CCB9A0: [rsp+0x20]=&{SECRET_A ptr, len=0x20}, [rsp+0x28]=esi
out1 = sub_141CCB9A0(&out1 /*rsp+0x70*/, &loc /*rbp*/, r8=rA, r9=ctx+0xE0)   ; CORE KDF
out2 = sub_141CCBF30(&out2 /*rbp-0x70*/, node+0x30 /*32B DB salt*/, r8=out1, r9=ctx+0xE0)
free(out1); free(outPre)

; ---- format out = "x'" + hex(out2 bytes) + "'" ----
out = ""                                        ; std::string at r12
tmp = "x'"                                      ; 2 bytes from word @[rip+0xd20728]
for b in out2[begin..end]:                      ; loop 0x141CCAEAB..0x141CCAFE9
    append format("%02x"-ish, b) to out         ; via sub_14057b2c0 (fmt @ [rip+0xb48fbc])
append "'" to out                               ; 1 byte @ [rip+0xb4bdb1], sub_14057f510
unlock(ctx->srw)                                ; sub_142374250
return out
```

So the final 32-byte raw key is **`out2`** (hex-encoded, wrapped as `x'...'`), produced by
the two-stage KDF `CCB9A0`→`CCBF30`.

## KDF inputs (what actually feeds the key)

| input | location | note |
|---|---|---|
| SECRET_A | `ctx+0x68` (32B, inline) | high-entropy; stable across restarts (from `mss.dat`) |
| DB salt | `node+0x30` (32B) | per-DB; **not** the file's 16B kdf_salt |
| label `"v2:"` | `ctx+0x100` (std::string) | KDF version/label |
| iter/mode `esi` | `(*(ctx+0xD8))->vtbl[0x10]()` | small int |
| `ctx+0xE0` | pointer struct | **NOT key data** — OpenSSL lib/provider context handle (heap around it holds TLS/cert strings like "www.digicert.com") |

## Why static recovery stops here

`sub_141CCB9A0` sets up a 32-byte output buffer (`call 0x1421da9ec` with `ecx=0x20`) and then:

```
0x141CCBA52:  jmp 0x14444f323      ; -> Themida VM region (0x144xxxxxx)
0x141CCBA58:  jmp 0x14449dbb4
0x141CCBA5D:  jmp 0x14444efed
...
```

The actual digest/KDF math is **Themida-virtualized**, so the exact construction
(HKDF vs HMAC vs PBKDF2, OpenSSL `EVP_KDF`/`PKCS5_PBKDF2`) cannot be read from
instructions. Static doc 02 only saw a `"sha256"` parameter string reaching this function;
the surrounding algorithm is behind the VM. Decryption was instead completed by capturing
the *result* key spec from memory — see `docs/04` §8.
