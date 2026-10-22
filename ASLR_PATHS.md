# ASLR Path Analysis: Pure Zend Bypass vs. Address Leak

Date: 2026-10-21
Prerequisite: the no-ASLR pure HTTP RCE chain already works (`NOASLR_REPORT.md`).
Constraint: **fully remote, pure HTTP; no target-side custom PHP**. The target page only has
plain `echo` (no session calls).

This document only analyzes the two paths available once ASLR is enabled, and does not treat the
old custom-PHP leak/ROP results as valid deliverables.

---

## 0. Summary of Conclusions

| Path | Current assessment | Main blocker |
|---|---|---|
| Path 1: pure Zend, no-leak bypass | No reliable primitive found | Every controllable write is NUL-terminated; partial overwrite always corrupts one ASLR-related byte; no known fixed function addresses |
| Path 2: pure HTTP address leak | No usable entry point found under default configuration | Default `session.serialize_handler=php` rejects session keys containing `\|`; the old leaks need `php_serialize` + userland `__serialize` reentrancy |

Under the conditions "default php.ini + vanilla session page", ASLR has not been broken yet.
Below we give the experiments already performed, the source-code evidence, and next verifiable
avenues to pursue.

---

## 1. Recap of Existing Primitives

The key write primitive of the no-ASLR chain:

1. Request A OOMs, leaving a dangling `PS(http_session_vars)` zend_reference (R0).
2. Request B's 56B raw value buffer can overwrite R0, writing:
   - `R0+0x00` gc: refcount=1, type=IS_REFERENCE
   - `R0+0x08` val.value: arbitrary 8-byte pointer
   - `R0+0x10` val.type: 0x307 (IS_ARRAY_EX)
   - `R0+0x18` sources: 0
3. The dtor path:
   `zend_delete_global_variable` → `zval_ptr_dtor` →
   `zend_reference_destroy` → `zend_array_destroy(val.value)` →
   `zend_hash_destroy` → `pDestructor(&bucket->val)`.
4. The best carrier for the fake HashTable is the data of a **live 192B zend_string**
   (L=167), because it is not overwritten by the free-list `next` pointer through gc; its
   contents are a field value, fully controllable starting at data+0.

So under ASLR, what is missing is: `val.value` (a heap address) and/or `pDestructor`
(a libc/libphp code address).

---

## 2. Path 1: Pure Zend, No-Leak ASLR Bypass

Goal: without any leak, directly construct pointers/function pointers that are insensitive
to ASLR.

### 2.1 Approach A: Reuse the old reference's val.value = A0 (the real session HashTable)

- In A, the old reference's `val.value` points to the real session HashTable A0.
  Measured under no-ASLR: A0 = `0x7ffff5e03268` (`R0+0xf48`).
- If B does not overwrite R0's val.value, but instead lets A0's memory become an
  attacker-controlled fake HashTable, then knowing the heap base is unnecessary.
- Feasibility check:
  - A0 is a 56B HashTable structure (sizeof(zend_array)=56, bin 6).
  - A0's `pDestructor` was originally `ZVAL_PTR_DTOR` (a libphp pointer).
  - We need A0 to be re-occupied by a **live** allocation with controllable content,
    and `gc.type == IS_ARRAY`.
  - But in B there are two classes of allocation with controllable content:
    1. The raw value buffer of `multipart_buffer_read_body`: it is `efree()`d as
       soon as the field is processed; after release, the allocator writes
       `next_free_slot` to block offset 0, overwriting gc, so `GC_DELREF` does
       not reach zero and the array dtor is never entered.
    2. Live zend_strings: gc type is IS_STRING (6), and `rc_dtor_func` calls
       `zend_string_destroy`, not `zend_array_destroy`.
  - A live real HashTable has the correct type=7, but its `pDestructor` is the real
    `ZVAL_PTR_DTOR`, which we cannot change without modifying gc.
- Conclusion: reusing A0 requires an allocation that is "live, controllable,
  type=IS_ARRAY"; none currently exists.

### 2.2 Approach B: partial pointer overwrite (keep libphp's high bytes)

Idea: change A0's `pDestructor` from `ZVAL_PTR_DTOR` to another
function/gadget within libphp, overwriting only the low 2–3 bytes and keeping libphp's
base high bytes. This requires no leak.

Two problems must be solved:

1. **Can we write to A0+0x30 covering only the low bytes?**
   - String/raw buffer writes always carry one NUL:
     `zend_string_init` writes 0 at data[len]; `multipart_buffer_read_body`
     writes 0 at out[total].
   - If we write N bytes starting at `pDestructor`, the Nth byte is necessarily 0.
   - Example: overwriting the low 2 bytes gives controllable `b0,b1` with `b2=0`;
     overwriting the low 3 bytes gives controllable `b0..b2` with `b3=0`.
   - Among the high bytes of the target libphp address, `b3/b4/b5` all carry ASLR
     randomness; forcing a byte to 0 only holds if the corresponding byte of the
     target absolute address is naturally 0. That depends on the base and is unreliable.
2. **Can a useful target be found within a 2–3 byte range?**
   - Measured symbols of the current libphp build (unstripped):
     ```text
     zif_system          0x43a870
     zend_call_function  0x566d20
     zend_hash_destroy   0x5cbb90
     zend_array_destroy  0x5cbdc0
     zval_ptr_dtor       0x613c50
     ```
   - `zval_ptr_dtor` and `zend_call_function` are 0xacf30 apart (~700KB);
     `zif_system` is 0x1d93e0 away (~1.9MB).
   - A 2-byte partial overwrite can only jump within the same 64KB; the 3-byte
     option plus the forced b3=0 NUL again depends on base bytes. Currently no usable
     gadget falls within the same 64KB.
   - libphp only imports `popen` (visible via `objdump -T`), not `system`;
     `popen@plt` also needs the libphp base, and its second argument rsi is not controllable.
   - The old intel of `zend_call_function → zif_system` requires a fake FCI, which
     belongs to a different chain that needs the libphp base.

Conclusion: partial overwrite is the closest direction to the "pure Zend" idea so far,
but the NUL terminator is a hard blocker; unless a **terminator-free write of arbitrary
prefix length** can be found.

### 2.3 Approach C: allocator self-written pointers (free-list next / shadow)

- Offset 0 of a freed block holds a plaintext `next_free_slot` (a heap pointer);
  offset size-8 holds an XOR-encoded shadow.
- If the fake reference's val.value is placed at a freed block's `next_free_slot`
  position, the allocator will write a real heap pointer for us.
- But that pointer points at **the start of another freed block**, whose offset 0 is
  again a next pointer — not a valid array gc; `GC_DELREF` will not reach zero.
- Regarding alignment, R0+8 must be the slot start of some bin; with R0=0x...2320,
  R0+8=0x...2328 is only divisible by the 8B bin (page offset 0x328=808=8×101),
  and 8B blocks have no controllable content.
- Conclusion: we cannot directly obtain "a heap pointer pointing to a controllable
  fake HashTable".

### 2.4 Approach D: Fixed-address code

- The Apache main binary is PIE (`file /usr/sbin/apache2` = pie executable);
  `libphp.so` and libc are both subject to ASLR.
- The only fixed executable page is vsyscall `0xffffffffff600000`, offering only
  gettimeofday/time/getcpu — no arbitrary syscall/RCE.
- Neither the main binary nor the modules provide a directly usable fixed PLT entry
  for `system@popen@execve` (imports checked; and the PIE base is randomized).
- Conclusion: no fixed code address is usable.

### 2.5 Path 1 Summary

With the existing primitives, a no-leak pure Zend bypass requires one of the following:

- A **partial write without a trailing NUL** (capable of low-byte overwrites of
  A0->pDestructor while preserving high bytes);
- A **live, controllable, type=IS_ARRAY allocation** (able to re-occupy A0);
- A combination of **allocator self-written pointer + controllable content**;
- Some real libphp function pointer usable within the same 64KB.

None of these has been proven yet. The next most valuable step is measuring the
gadgets/functions within 64KB of `zval_ptr_dtor` in libphp, and looking for any PHP
allocation path that "writes N bytes without a terminator".

---

## 3. Path 2: Pure HTTP Address Leak

Goal: leak the heap chunk base / libphp base / libc base into the HTTP response,
then let the no-ASLR chain compute addresses dynamically.

### 3.1 Session serializer limits under default configuration (experimented)

Defaults:

```ini
session.serialize_handler = php
session.use_only_cookies = 1
```

The default `php` encoder, before writing each session key:

```c
smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
    /* key contains '|': abandon the whole encode and return NULL */
    fail = true;
    break;
}
smart_str_appendc(&buf, PS_DELIMITER);
php_var_serialize(&buf, struc, &var_hash);
```

Measured (gdb on `ps_files_write`):

```text
progress key = upload_progress_X|E:20:"AAAAAAAAAAAAAAAAAAAA";
FWRITE key=injtest0005 klen=11 vlen=0
php_session_decode len=0
```

That is: when the progress key contains `|`, the encoder returns NULL directly and the
session write is empty; the END cleanup reads session data of length 0. **Under default
configuration, keys cannot be used to inject arbitrary serialized data.**

The default decoder is not C-string parsing either:

```c
while (*q != PS_DELIMITER) {
    if (++q >= endptr) { retval = FAILURE; goto break_outer_loop; }
}
```

NUL cannot bypass the `|` delimiter.

### 3.2 Dependency of the old leak primitives (does not satisfy current constraints)

Both leaks in Section 10 of `NOTES.md` depend on:

1. `session.serialize_handler = php_serialize` (non-default; set via script `ini_set`
   or application configuration).
2. A userland class `C::__serialize()` that frees the `$_SESSION` array during the
   encode, then re-occupies it with `zend_reference`/`stream_bucket_new`, creating a
   UAF in the encoder.
3. The application calling `session_encode()` and outputting/storing the result in a
   readable place.

The current target page only has plain `echo`, no userland classes, and no
`session_encode()` output; the default handler is `php` besides. Therefore, under
these constraints, both leaks are unreachable.

### 3.3 The attacker-controllable session data surface under pure HTTP

Under the default configuration, the only things an attacker can influence that reach
the session file are:

- the progress key (the key name, which cannot contain `|`);
- the fixed keys/values of the progress data array:
  `start_time`, `content_length`, `bytes_processed`, `done`,
  `files[0].field_name`, `files[0].name`, `files[0].tmp_name`,
  `files[0].error`, ...
- Of these, `field_name`/`name` are attacker strings, but they are written as
  **serialized values** (`s:<len>:"...";`), binary-safe; they cannot become keys or enums.

The structure the session decoder reads is generated by PHP itself; there is no
attacker-controlled `E:`/`O:`/`C:`/`R:` syntax and no cross-variable injection.

### 3.4 Candidate leak points and blockers

| Candidate | Result |
|---|---|
| progress key injecting serialized `E:` → enum warning `%.*s` | The default `php` encoder rejects keys containing `\|`; 0 bytes written |
| `E:` out-of-bounds length read | `maxlen < len` check; len is bounded by the input buffer length |
| session file as leak carrier | Requires an encoder OOB write first; the default encoder has none |
| OOB/warning in `unserialize` built-in class handlers | Under default configuration `O:`/`C:` cannot be injected; progress data only has arrays/strings |
| Error info `%p`/pointer formatting | The session/unserialize paths have no `%p`; only the enum's `%.*s` |
| `session_start` warning printing id/path (only a candidate when the app calls it) | Contains no memory addresses; the id charset is restricted |
| `/proc/self/maps` | Requires target-side PHP to read files, violating the constraint |

### 3.5 If php.ini may be changed (not application PHP)

With `session.serialize_handler` changed to `php_serialize`:

- the `|` in progress keys is no longer rejected by the encoder
  (`php_serialize` serializes the whole array with `php_var_serialize` and never
  checks keys for `|`);
- keys can inject extra session variables, triggering decode warnings/built-in
  class handlers;
- but the two old leaks still require the reentrancy of "freeing the session array
  during encode", which the vanilla page does not have.

So even changing the INI does not automatically give a leak; a reentrancy gadget built
purely from PHP internals is still needed, and has not been found.

---

## 4. Next Experiments for Both Paths

### Path 1 (pure Zend)

1. **Measure the libphp layout**: use `nm -D`/`objdump` to obtain the offsets of
   `zval_ptr_dtor`, `zend_call_function`, `zif_system`, `system@plt`, and confirm
   whether a usable partial target exists within the same 64KB/16MB.
2. **Look for terminator-free writes**: check paths like `erealloc` growth, stream
   buckets, `smart_str` for allocations that "copy only a prefix, without writing a
   NUL"; if found, a true low-byte partial overwrite of A0->pDestructor becomes possible.
3. **Live re-occupation of A0**: attempt to have A0 (a 56B HashTable) re-occupied in
   B by a **live** controllable allocation while keeping `gc.type=IS_ARRAY`;
   for example:
   - use session decode to generate a real small array that lands on A0;
   - then use a write that only covers pDestructor's low bytes and leaves gc intact.
4. **Allocator pointer alignment**: scan A's parameters (progress key length, SID
   length, file count/sizes) to see whether R0 can move so that R0+8 becomes the slot
   of a larger bin, letting the free-list next pointer yield a heap pointer that
   "points controllably".

### Path 2 (leak)

1. **Only under the default configuration**, enumerate all paths that can output an
   attacker string into a warning (`php_error`'s `%s`/`%.*s`) and confirm whether any
   `%.*s` has an unvalidated length.
2. **Fuzz the handlers of built-in `Serializable` classes**: the `unserialize()` C
   implementations of `ArrayObject`, `SplObjectStorage`, `DateTime`,
   `SimpleXMLElement`, `ZipArchive`, `Phar`, etc., looking for out-of-bounds reads or
   paths that print input into warnings. Note that under the default configuration
   `C:`/`O:` currently cannot be injected into the session, so this line only matters
   with `php_serialize` or app-controllable session data.
3. **Progress data values**: confirm whether `field_name`/`name`/`tmp_name` are ever
   printed via `%.*s` on any error path; none found in the sources so far.
4. **BG(unserialize) write primitive**: if `serialize_lock` dependencies can be
   bypassed under pure HTTP, `var_push`'s arbitrary write could forge a
   `zend_string.len`, then trigger a `%.*s` warning to leak. That chain is currently
   paused because it needs application-level `__wakeup`/autoload.

---

## 5. Assessment Under the Constraints

- **Pure Zend, no leak**: theoretically the most elegant, but limited by the
  "NUL terminator + no fixed code address" issues; there is no reliable construction yet.
- **Address leak**: under the default `php` serializer, progress key injection is
  rejected outright by the encoder's `memchr('|')`; the old leaks in turn depend on a
  non-default serializer + userland reentrancy. Under pure HTTP with no application
  code, no leak entry point has been found.
- If a **non-default php.ini** is allowed (`session.serialize_handler=php_serialize`),
  key injection + built-in class handlers can be researched further; this still is not
  "writing custom PHP", but it has already departed from the default configuration.
- If the target application may host a session object/progress endpoint (an application
  gadget), the old `php_serialize` leak chain can be reused; that is an application-layer
  dependency and does not meet the current "vanilla session page" constraint.

Under the strict constraints, the current deliverable should be clearly labeled as
**no-ASLR RCE**; neither ASLR path is complete, and one of the experiments above must
break through.

---

## 6. Addendum: Measured Fixed Zend Offsets (2026-10-21)

After the hint that "some Zend addresses may be fixed", the following measurements were
made.

### 6.1 Fixed Offsets

With ASLR on (`randomize_va_space=2`), reading via A/B triggering at
`php_session_track_init`:

- The old reference R0 = **chunk + 0x2320**, identical across three master restarts.
- The session HashTable A0 (R0->val.value):
  - A's PHPSESSID length 8..32: A0 = **chunk + 0x3268**
  - A's PHPSESSID length 1..5: A0 = **chunk + 0x3230**
- The Zend main chunk base is 2MB-aligned.
- Under the same Apache master, killing the worker with -9 five times in a row left
  the new worker's chunk base completely unchanged (e.g. `0x7fa32de00000`, B=7). That is:
  - **the chunk base is fixed within one master's lifetime**;
  - but only a master restart re-randomizes it; worker crashes cannot be used to retry B.

### 6.2 The chunk header is not a code trampoline

Dumping chunk+0x000..0x100:

- `heap`/`next`/`prev`/`free_slot[]` are all heap pointers;
- `size`/`peak`/`chunks_count`/`pid` are small integers;
- no libphp/libc code pointers.
- A 1-byte partial write can only point the old val.value to `chunk+0x00XX`, which
  lands exactly in the header with no usable pDestructor; a 2-byte partial write
  zeroes b2 (low 3 bits of the 2MB index within a 16MB block); measured, that slot is
  the library's read-only `.eh_frame` data, not a controllable Zend chunk.

### 6.3 A0's old contents

The old HashTable at A0=chunk+0x3268:

```text
A0+0x00 gc        = 0xffffffff00000106   (refcount is not 1)
A0+0x10 arData    = chunk+0x33c0
A0+0x30 pDestructor = libphp zval_ptr_dtor (real code pointer)
```

Because the refcount is not 1, without overwriting val.value the dtor only decrements
the reference and never enters `zend_array_destroy`; hence the reference had to be
forged previously.

### 6.4 New primitive: writing a binary PHPSESSID into A0's gc

- `php_session_valid_key()` scans as a C string; the PHPSESSID value can be
  `validprefix\0<binary>`, and the binary after the NUL still ends up in the
  zend_string of `progress->sid` / `PS(id)`.
- `PS(id)` is created by a direct `zend_string_init`; its raw value buffer is freed
  first, then the 320B PS(id) reuses that slot.
- Measured: SID length 280, `sidvalid\0...` + a fake gc placed at SID offset 0x110;
  at B's track_init, **A0's first qword became
  `0x0000000700000001`**, without knowing the chunk base at all.
- That 320B live string is at page3 slot 0x3140 (data at 0x3158) and
  A0=0x3268 is exactly data+0x110.
- That means: **the gc (refcount=1, type=IS_ARRAY) can be written relative to A0**.

### 6.5 Still unsolved: pDestructor / arData

- With A0=0x3268, pDestructor sits at A0+0x30=0x3298, which crosses into the **next
  320B slot** (0x3280); measured, that place got overwritten by B's 320B allocation
  with `0xffff...`, losing the old real `zval_ptr_dtor`.
- If A's SID is changed to length 1..5, A0=0x3230 and pDestructor falls inside the
  same 320B slot; but:
  - to overwrite/control gc/flags/arData, the 320B string length must be ≥257, and
    with pDestructor at data offset 0x108=264, the string copy would **fully
    overwrite** pDestructor (high bytes cannot be preserved);
  - to preserve pDestructor, the length must be ≤263, in which case arData (data
    offset 0xd8+0x10=232) is already overwritten, and an absolute pointer must be
    written — with an unknown base;
  - to overwrite only gc/flags without touching arData, L<232 would be needed, but
    the 320B bin requires L≥257; the bin size and the copy length are coupled and
    this cannot be done.
- The 8B header key approach also fails: R0+8=0x2328 within page2 is only 8-byte
  slot-101 aligned, and page2 is occupied by startup-time 56B allocations
  (MAP2=bin6), not bin0; moreover an 8B block's free-list shadow covers the whole
  8 bytes, so the old high bytes cannot be preserved.

### 6.6 Conclusion

The fixed Zend offsets are real and usable:

- R0, A0, and the fake HT's offsets relative to chunk are fixed;
- the chunk base is fixed within one master;
- the old real `zval_ptr_dtor` pointer sits at A0+0x30.

But these alone still cannot bypass ASLR, because:

1. a partial write that **writes no NUL and only changes the prefix** is needed to
   preserve pDestructor's high bytes;
2. or arData must be pointed at a fake bucket with **a controllable absolute address**;
3. all currently usable writes are "whole-segment copy + NUL terminator", with fixed
   bin geometry, and neither of the above has been constructed.

The most worthwhile next steps:
- use A's parameters to move A0 to some address where "the string data ends at
  pDestructor+1" coincides with the bin/slot geometry (currently neither 0x3230 nor
  0x3268 satisfies this);
- or find any Zend allocation/copy path that "writes only N bytes without a terminator";
- or leak the chunk base first (fixed within one master, so one leak is reusable).

---

## 7. Addendum: A0 Forms and the page3 Bin, Measured

### 7.1 A0 has more than two values

Fine-scanning A's PHPSESSID length (no-ASLR, page3 fixed 320B bin):

| A SID length | A0 (chunk offset) | gc at A0+0 | A0+0x30 |
|---|---|---|---|
| 1–13 | `0x3230` | `0x80000000005978e8` (not an array HashTable) | `0x7ffff5e61208` |
| 14–21 | `0x3268` | `0xffffffff00000106` (huge refcount) | real `zval_ptr_dtor` |
| 22–23, 32–40 | `0x3230` | same as above | not pDestructor |
| **24–30** | **`0x3310`** | **`0xc000040700000001`** (rc=1, type=IS_ARRAY) | **real `zval_ptr_dtor`** |

`0x3310` is the first A0 encountered that "is itself directly usable as a
HashTable":

```text
A0=chunk+0x3310
A0+0x00 = 0xc000040700000001   gc: rc=1, type=IS_ARRAY
A0+0x10 = chunk+0x4900/0x4540  arData (real heap pointer)
A0+0x30 = libphp zval_ptr_dtor (real code pointer)
```

In other words, **without forging gc/flags**, the stale reference's val.value=A0 and
`zend_array_destroy(A0)` will take the real array path.

### 7.2 page3's bin is fixed

Under ASLR/no-ASLR, B's chunk page map is always:

```text
page1 bin3 (32B)
page2 bin6 (56B)
page3-7 bin16 (320B)
page8-12 bin20 (640B)
```

Testing with the custom request header `X-Pad: A*N` (N=0/96/320/480/700/1000), the page
map does not change at all. Catching the first 320B allocation in gdb at
`zend_mm_alloc_small_slow`:

```text
zend_mm_alloc_small_slow(bin_num=16)
  zend_hash_real_init_mixed_ex
  zend_hash_real_init_mixed
  _zend_hash_add_or_update_i
  zend_hash_add
```

The first 640B allocation is the same HashTable's `zend_hash_do_resize`. So page3's
320B bin is fixedly allocated by startup-time HashTable arData, and **cannot be changed
via request headers/fields**.

### 7.3 320B slot geometry and A0=0x3310

A0=0x3310 lies in page3's 320B slot2 (block `0x3280`, data `0x3298`):

```text
A0 = 0x3310 = slot2 data + 0x78
arData       = A0+0x10 = slot2 data + 0x88
nNumUsed     = A0+0x18 = slot2 data + 0x90
pDestructor  = A0+0x30 = slot2 data + 0xa8
```

- A 320B zend_string's data in slot2 starts at 0x3298, and its length can only be
  232..295.
- To overwrite/control pDestructor (data offset 0xa8=168), the copy must be ≥168
  long; but the 320B bin's minimum length is 232, so the copy **necessarily covers
  arData** (offset 0x88=136) and the preceding gc/flags as well.
- To NUL only pDestructor's byte 0 (preserving high bytes), L=168 would be needed;
  that corresponds to alloc=193 → the **224B bin**, which cannot occupy 320B slot2.
- To preserve arData (not overwriting it), L<136 would be needed — even less likely
  to occupy the 320B slot.
- Therefore, although A0=0x3310 has a valid gc, it is still stuck on "copy length vs.
  bin size": a partial overwrite of pDestructor while preserving arData is impossible.

### 7.4 Current assessment

- The fixed Zend offsets do exist, and A0=0x3310 provides a real, rc=1
  controllable starting point;
- but page3's 320B bin is fixed, and the 320B slot's data-length window (232..295)
  does not match A0's internal field offsets (arData 136, pDestructor 168);
- we still lack a write primitive that "writes only a prefix, no NUL", or a relative
  pointer that can make arData point at controlled data.

This line is not closed yet; the no-ASLR RCE remains the only verified code execution.
