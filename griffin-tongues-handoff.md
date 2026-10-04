# Griffin Tongues — RE Handoff

**Challenge:** Griffin Tongues (1000 pts)
**Remote:** `nc 0.cloud.chals.io 23572`
**Binary:** `griffin_tongues` — attached alongside this file, MD5 `d70ee171d9f980d7e22cc8f06cf96842`
**Goal:** get the binary to hand back the flag over the nc connection.

Attached files for handoff:
- `griffin_tongues` — the target binary
- `emu.py` — a custom x86-32 emulator built specifically for this binary (see below)

---

## 1. What kind of binary this is

- ELF32, Intel 80386, statically linked, **stripped**, only 4200 bytes.
- Entry point `0x8048060` jumps straight to `0x8048128`, skipping a chunk of dead/junk bytes deliberately placed to desync linear disassemblers (objdump, etc. produce garbage if you disassemble straight from file offset 0).
- Written in raw hand-assembled x86 using **direct Linux syscalls via `int 0x80`** (no libc).
- **Self-modifying**: the code repeatedly does `mov edi, TARGET; mov ax, OPCODE_BYTES; stosw` to write 2-byte opcodes (usually `cd 80` = `int 0x80`, sometimes other 2-byte instructions) into the `.text` section at runtime, directly over bytes that look different in a static disassembly. **Static disassembly of this binary is actively misleading** — you cannot trust `objdump` output beyond general shape; the real instruction stream only exists after self-modification happens at runtime.

**Conclusion reached:** static analysis tools (objdump/readelf) are not sufficient here. The approach that worked was writing a **custom Python x86-32 interpreter** that executes the binary's actual mutable byte buffer (so self-modification "just works" naturally), rather than trying to hand-resolve every obfuscated jump.

---

## 2. The emulator (`emu.py`)

A from-scratch x86-32 interpreter, no external dependencies (no network access was available to install capstone/unicorn/qemu — pip and apt are both blocked in this sandbox, so everything was hand-rolled).

Key design:
- Flat mutable `bytearray` memory, `BASE = 0x08040000`, `SIZE = 0x00100000` (1MB).
- Loads the binary per its single PT_LOAD segment: file offset `0x60` → vaddr `0x8048060`, filesz `0xf23`.
- Registers, flags (ZF/SF/CF/OF only — PF/AF not tracked, hasn't mattered yet).
- Generic ModRM/SIB decoder supporting register and memory operands (direct, `[reg+disp]`, SIB-based `[esp+disp]`, etc.)
- Syscalls are intercepted in `do_syscall()` — fake/stub implementations for ptrace, vfork, uname, etc. (all return success/0), plus a **fake oracle** at `127.0.0.1:1337` controlled by `FAKE_ORACLE_RESPONSE[0]`, and fake stdin/stdout via `STDIN_DATA[0]` / `STDOUT[0]`.
- Entry: just run `emu.run()` after setting `emu.STDIN_DATA[0]` and `emu.FAKE_ORACLE_RESPONSE[0]`.

### Bugs already found and fixed during this session (don't re-waste time on these):
1. `stos`/`movs` originally ignored the `0x66` operand-size prefix and always wrote 4 bytes — this corrupted adjacent self-modified code during emulation (cost significant debugging time). **Fixed** — now respects 16-bit vs 32-bit operand size.
2. `rep`/`repz`/`repnz` prefixes weren't implemented (string instructions only ran once). **Fixed** — `step()` now loops using `ecx` and respects `repz`/`repnz` early-exit on `cmps`/`scas`.
3. Missing opcodes added as encountered: `0x04/0x0c/0x14/.../0x3c` and `0x05/0x0d/.../0x3d` (AL/eAX-immediate arithmetic group — add/or/adc/sbb/and/sub/xor/cmp with the accumulator).
4. A couple of leftover `NameError`s in exception-formatting strings (referenced an out-of-scope `start` variable after a refactor) — fixed, cosmetic only.

The emulator currently runs cleanly (no unknown-opcode crashes) from entry through: anti-debug checks → socket()/connect() to `127.0.0.1:1337` → `recv()` of a 53-byte response → `close()` → into a validation routine on the received data → an `unlink("tmp")` call → a tight XOR-decode loop → more validation → **exit(255) on validation failure**, because the fake oracle response doesn't satisfy the hardcoded checks (expected, since we don't have the real oracle).

---

## 3. Key findings so far

### 3.1 The internal "oracle"
- The binary opens a TCP connection to **127.0.0.1:1337** (`socket()` with `AF_INET`/`SOCK_STREAM`, then `connect()`) and does a single `recv()` of up to 1023 bytes (actual observed/expected real response size appears to be **53 bytes**) into a `.bss` buffer at `0x8048f84`.
- This is presumably a **server-side-only service** on the real challenge infrastructure that hands back the actual flag/secret material. It is **not reachable or fakeable by the player** — it's invisible to whoever connects over `nc`. This exchange happens entirely before any player interaction that we've found so far.
- **Important unresolved question:** we have NOT yet confirmed whether the player's nc session actually reaches this oracle-validation code path at all, or whether it's dead/decoy code. Needs verification once further down the control flow.

### 3.2 Decoded `.data` fragments (via XOR key `0x7b`)
Not all of `.data` is wrapped with the same key — only confirmed for the chunk at `0x8048d27` (16 bytes). Decoding:
```python
d = open('griffin_tongues','rb').read()
chunk = d[0xd10 + (0x8048d27-0x8048d10) : 0xd10 + (0x8048d27-0x8048d10) + 16]
print(bytes(b ^ 0x7b for b in chunk))
# => b'F34rTh3R3aper540'
```
- `0x8048d10` (file offset `0xd10`): first 3 bytes, compared **raw** (no XOR) = `\xdc\x54\x00` — this is checked against the first 3 bytes of the oracle's 53-byte response directly. Likely a protocol/version magic header the real oracle always sends, not something to brute force.
- `0x8048d27` (16 bytes) XOR `0x7b` → `"F34rTh3R3aper540"` — only the **first 8 bytes** (`"F34rTh3R"`) are actually compared (loop uses `ecx=8`, not 16) against received-buffer offset 27.
- `0x8048d37` (10 bytes), compared **raw, no XOR** = `"V#c7$3!k4@"` — compared against a received-buffer offset overlapping/adjacent to the above (exact offset not yet pinned down precisely — see open items).
- Also decoded cleanly with key `0x7b`: `/usr/bin/md5sum` (right at `.data` start) — the binary likely shells out to or otherwise uses `md5sum` somewhere (possibly hashing the "tmp" file it opens/unlinks, or verifying its own binary — needs tracing).
- A separate filename string `"tmp"` lives at `0x8048d23` (used in an `open()`/`unlink()` pair — opens a file named `tmp` in CWD, then unlinks it).

### 3.3 The real suspected puzzle: ~30-call quiz loop
Starting around `0x804830e`, there's a long flat sequence of:
```
call <question_function_N>
call 0x8048ca9      ; shared helper — likely "print prompt / read answer / check"
call <question_function_N+1>
call 0x8048ca9
... (~30 pairs total)
```
This is almost certainly the actual **"Griffin Tongues"** interactive quiz — a translation/word quiz the player answers over stdin, matching the challenge flavor text. **We have not yet reached this code path in emulation** — execution currently dead-ends at the oracle-validation `exit(255)` before getting here.

---

## 4. Exact next step (where to resume)

There are **9 known static jump sites** that branch to a shared "fail" handler at `0x8048d04` (which just does `exit(255)` — confirmed via `objdump`: `mov eax,1; mov ebx,0xff; int 0x80`). Found via:
```bash
objdump -d -M intel --start-address=0x8048128 --stop-address=0x8048d10 griffin_tongues | grep 0x8048d04
```
Result (addresses of the jcc instructions themselves):
```
0x8048162  jl   0x8048d04
0x8048211  jl   0x8048d04
0x804829a  jle  0x8048d04
0x80482ca  jne  0x8048d04
0x80484fd  jne  0x8048d04
0x80485f2  jne  0x8048d04
0x804860d  jne  0x8048d04
0x8048630  jle  0x8048d04
0x8048cdf  js   0x8048d04
```
**Next action:** patch the emulator to force all 9 of these to fall through (never taken), e.g. by hooking `execute_one` to detect `RIP == 0x8048d04` right after executing one of these addresses and redirecting back to the correct fall-through (= address of jcc + its instruction length — for the `0f 8x` two-byte-opcode conditional jumps this is `start+6`; for the `78 23` short jump at `0x8048cdf` it's `start+2`). This was in progress when the session paused — a quick pattern like:

```python
SKIP_TARGETS = {
    0x8048162: 6, 0x8048211: 6, 0x804829a: 6, 0x80482ca: 6,
    0x80484fd: 6, 0x80485f2: 6, 0x804860d: 6, 0x8048630: 6,
    0x8048cdf: 2,
}
orig = emu.execute_one
def wrapped(op, opsize):
    pre = emu.RIP[0]
    if pre in SKIP_TARGETS:
        emu.RIP[0] = pre + SKIP_TARGETS[pre]
        return True
    return orig(op, opsize)
emu.execute_one = wrapped
```
Then run with `emu.STDIN_DATA[0] = b'\n'*5000` (or better, instrument `read()`/`write()` to log interactively) and `emu.FAKE_ORACLE_RESPONSE[0]` set to anything 53 bytes long (content won't matter once checks are bypassed) — and watch `emu.STDOUT[0]` to capture the actual quiz prompts, plus add a hook on the `write`/`read` syscalls (already logged to console in `do_syscall()`) to reconstruct the full Q&A script.

**Goal of that run:** extract the literal prompt text and expected-answer-checking logic for all ~30 quiz entries, so the human can answer them correctly over the real `nc` session (where the real oracle — which we can't fake — will supply the actual flag content once the quiz is passed, presumably).

---

## 5. Open questions / things to verify next

1. Does the player's nc session actually go through the oracle-connect code at all, or is there a fork/branch earlier that separates "internal setup" from "player-facing interaction"? (The `vfork` syscall near the very start is suspicious — may fork into a child that talks to the player while a parent does setup, or vice versa. Not yet traced.)
2. What exactly triggers sending the flag back to the player — is it printed after all 30 quiz answers are correct, or is there a partial-credit / specific subset needed?
3. Confirm the exact byte offset used for the `"V#c7$3!k4@"` 10-byte raw check (was mid-trace when session paused — overlapping offset math needs re-verification with the instrumented `CMPS_HOOK` already added to `emu.py`).
4. Is `/usr/bin/md5sum` actually invoked (via some exec syscall not yet encountered), or just referenced/unused?
5. Once the quiz prompts are extracted, cross-reference against the challenge name "Griffin Tongues" — likely a constructed-language / translation gimmick (Pig Latin, leetspeak, phonetic alphabet, etc.) based on patterns like `"F34rTh3R3aper540"` already decoded (looks like leetspeak itself — "FearTheReaper540").

---

## 6. Practical notes for whoever picks this up

- No network access in this sandbox — pip/apt installs fail silently with 403s. capstone/unicorn/qemu are NOT available; the hand-rolled emulator in `emu.py` is the only execution path. If your environment DOES have network/qemu-user/gdb, those would likely be faster than continuing with this emulator — but `emu.py` already works for everything encountered so far and is a reasonable base to keep extending if not.
- `emu.py` is a single file, no dependencies beyond the Python standard library (`struct`, `socket` import exists but is unused currently — safe to ignore/remove).
- Useful instrumentation already built into `emu.py`: `CMPS_HOOK[0]` — set to a function `(esi, edi, byte_a, byte_b)` to observe every byte comparison live, which was the key technique that cracked the self-modified/obfuscated validation logic so far.
