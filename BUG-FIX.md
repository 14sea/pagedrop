# Bug fixes

Confirmed defects in `pagedrop.c`, and the checks that caught them. Trace validation was not used. Model checks used the TLC jar already in `../Specula/lib`.

## `exact=1` did not apply to `comm`

`pb_is_target` still used `strstr` on `current->comm`. `exact=1` only affected the exec pathname check, so a shorter token still tracked the process.

Fix: the comm check calls `pb_name_matches`. The suite loads `path=extr exact=1` and requires `extra epoch` to miss, then `path=extra exact=1` to pass.

## A data read was logged on every fault

`pb_handle_data` appended `ip data_va epoch` after every swallowed read. If the page had already been dumped for that handler epoch, `epoch` was 0.

Fix: append one line, and only after a successful dump. The epoch is the handler epoch. `extra read` still passes.

## `data=` stopped after the first armed page

The first successful `PROT_NONE` set a process-wide flag. A page mapped later in the range was never armed. A successful exec left the flag set, so the next image was not armed either.

Fix: remember each armed page. Retry pages that are not mapped yet. Clear that state on successful exec.

## `fork` killed a child on an armed data page

`data=` sets the range to `PROT_NONE`. `fork` recorded the child tgid and did not copy the tracked-page list. The child inherited the protection. The fault hook did not restore the page, because the child's instruction pointer was not in its own list, and delivered `SIGSEGV`.

TLC trace: Arm, Fork, ChildRead, `dead = TRUE`. On the x86 guest, `/tmp/forkarm` printed `child exit 0` with the module unloaded and `child signal 11` with `path=forkarm data=260000000-260001000`.

Fix: copy the parent's tracked pages and armed-data list to the child. Restore an armed data page even when the faulting instruction is not in the tracked list. `extra forkread` covers this on both arches.

## A non-matching exec left tracked pages behind

A tracked process that execs a path which does not match keeps its tgid. The old page list was dropped only when the new path matched. The new address space does not contain those pages. An instruction fault at an old address still matched the list. `mprotect` failed, and the hook returned 0, so the fault retried until `SIGALRM`.

Exit deleted the tgid record and left the same list. A reused tgid could attach those pages to the next process.

TLC trace: Track, ExecOther, Jump, `hung = TRUE`. Before the fix, `path=staleexec` exited 139 (`SIGSEGV`) with the module unloaded and 142 (`SIGALRM`) with it loaded.

Fix: drop that tgid's pages on a non-matching exec and on exit. If `mprotect` fails in the fault hook, deliver the signal. `extra stale` must die with `SIGSEGV` (exit 139), not hang.

## Arming a read-only page made it writable

`pb_handle_data` restored every armed page as `PROT_READ|PROT_WRITE`. A `PROT_READ` page in `data=` was set to `PROT_NONE`, then came back writable after the read fault. A later store succeeded.

TLC trace: Arm, Read, Write, `wrote = TRUE`. On the x86 guest, `/tmp/roarm` exited 3 with the module unloaded (the write faulted) and printed `write 1` with `path=roarm data=260000000-260001000`.

Fix: save the VMA's read/write bits when arming, and restore those bits. `extra roarm` requires the following store to fault. Both full suites passed after this fix.

## `mremap` left an armed page inaccessible

`data=` sets a page to `PROT_NONE` and records that address. `mremap` moved the mapping and left the record at the old address. A read at the new address was not restored. Outside the `data=` range the fault hook ignored it, so the process died with `SIGSEGV`.

TLC trace: Arm, Move, Read, `dead = TRUE`. On the x86 guest, `/tmp/moveread` printed `moved B` with the module unloaded and exited 3 with `path=moveread data=260000000-260001000`.

Fix: move the armed record when the new address is still in range, and restore the saved protection when it is not. `extra moveread` covers both, with `data=260000000-260001000` and `data=260000000-280000000`.

## `munmap` left the armed record behind

`data=` records a page and sets it to `PROT_NONE`. `munmap` removed the mapping and left that record. A new mapping at the same address was not armed again, because the next arm attempt skipped an address already on the list. The new bytes were read with no fault and no trace line.

TLC trace: Arm, Unmap, Remap, TryArm, Read, `missed = TRUE`. `/tmp/rearm` printed `trace 1` and exited 2, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: `munmap`, and a replacing `mmap`, drop armed, seen, and tracked entries for that range. `extra rearm` passed twice on each arch, then the full suite once on both.

## A store into an armed page was not restored

`data=` makes the page inaccessible and the fault hook restores it only on a read. A store is a write fault. The hook delivered `SIGSEGV` even when the saved protection included write.

TLC trace: Arm, Write, `dead = TRUE`. `/tmp/wrarm` exited 3, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: a write fault on an armed page is restored too, but only if the saved protection includes write. A write to a page that was read-only still faults. `extra wrarm` and `extra roarm` passed twice on each arch, then the full suite once on both.

## Making an armed page executable dumped nothing

`data=` sets the page to `PROT_NONE`. A later `mprotect` to execute dumps the page before that protection is installed. `copy_from_user` fails, so the marker never reaches a dump.

TLC trace: Arm, MprotectX, `missed = TRUE`. `/tmp/noneexec` printed `dump 0` and exited 2, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: if the range is armed, restore a readable protection before the dump. `extra noneexec` passed twice on each arch, then the full suite once on both.

## `mprotect` left the armed record behind

`data=` records a page and sets it to `PROT_NONE`. A later `mprotect` of that page changed its protection but left the record. The next arm attempt skipped an address already on the list, so the page was never made inaccessible again and nothing was traced.

TLC trace: Arm, MprotectW, TryArm, Read, `missed = TRUE`. `/tmp/disarm` printed `trace 0` and exited 2, twice on x86 `6.8.0-101-generic` and twice on arm64 `6.6.62+rpt-rpi-v8`.

Fix: any `mprotect` drops armed and seen records for that range, so the next arm attempt re-arms a non-executable page. `extra disarm` passed twice on each arch, then the full suite once on both.

## A forked child could fault before the parent finished the copy

`real_sys_fork` returns in the parent and in the child. The parent's `pb_note_child` copies the tracked pages and armed records into the child tgid, but it runs after the fork has already returned. A child that reads an armed page in that window has no record of its own, so `pb_handle_data` found nothing, returned 0, and the real `SIGSEGV` was delivered. The child died.

Observed once: an x86 suite run reported `forkread: child died`. It did not recur in 30 standalone `forkread` runs, three ordered `read` then `forkread` sequences, or two later full suites on both arches.

Fix: a data fault also consults the parent tgid's armed record and tracked page, which is correct because `fork` shares the page tables. `extra forkrace` runs 200 fork-and-fault children per invocation and is now part of both suites.

What was not shown: `forkrace` passes 200 iterations both with and without the parent fallback, because the test waits for each child, so the parent always wins the lock. The fix rests on the code reading and the one observed failure, not on a reproducing test. If the failure returns, this fallback is the first thing to check.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. With `useParent = FALSE` the fault handler consults only the child tgid and TLC reports the counterexample Fork, ChildFault, `sigdeliv_child = TRUE`, with no copy in between. With `useParent = TRUE` the property holds over the whole state space. That is the evidence the window is real and the fallback closes it.

## A child's records survived the child's own exit

`pb_note_child` runs in the parent after the fork: `pb_tgid_add`, then `pb_copy_tracking`. The child can run and exit in between. Its `do_exit` drops records that do not exist yet, and the parent then registers a tgid that is already dead and copies pages into it. That tgid stays in the tracking list, so a later process that reuses that pid is treated as a target and inherits stale pages. This is the exit-leak class above, on the child side, and it was introduced by the `fork` fix.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. Property `EventualClear`, with weak fairness on the cleanup so stuttering cannot starve it. `useFix = FALSE` reproduces the shipped order and TLC reports `Temporal property EventualClear was violated` on Fork, TgidAdd, CopyBegin, CopyLand, ChildExit, with the tgid still registered and the records still copied. `useFix = TRUE` satisfies the property.

Fix: do not register a tgid whose task has already exited, and drop the records again if the child died while the copy ran. `pb_child_alive` uses `find_vpid` and `get_pid_task`. Both suites pass, including `extra forkrace` and `extra pair`.

## Two threads could dump the same data page twice

`pb_handle_data` tested `data_seen`, then ran `dump_to_file` with no lock held, then added the record. The test and the insert were not one critical section, so two threads faulting the same armed page in the same handler epoch could both observe an empty list, both dump, and both write a trace line. That breaks the documented "dumped once per handler epoch" and gives `pb_rank` two index rows for one address.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. TLC reports Seen1, Seen2, Dump1, Dump2, Dump1Done, Dump2Done, with `dumps = 2` and `traces = 2`, violating `Safe`.

Reproduced on x86 `6.8.0-101-generic`: 8 threads released from a barrier onto one armed page produced 2 trace lines in 8 of 8 runs. Four threads produced 1. The count grows with the thread count, which is the signature of a lost update rather than a coincidence.

Fix: `pb_data_claim` tests and inserts under one `marea_lock` hold, and `pb_data_unclaim` releases the claim if the dump then fails, so a later fault can retry. `extra dumprace` requires exactly one trace line from 8 barriered threads. It failed 8 of 8 before the fix and passed 4 of 4 on x86 and 3 of 3 on arm64 after it, with the full suite passing on both.

## A reader could take a real SIGSEGV while the module was arming or disarming

`data=` deliberately makes a page inaccessible so the fault reveals which handler consumed it. Both the arming and the disarming had a window where the page was `PROT_NONE` with no armed record. `pb_handle_data` found nothing and returned 0, so `fh_force_sig_fault` fell through to the real handler and the process took a signal that the module had caused itself.

Two windows, both in the shipped code:

- Arming: `pb_arm_range` called `pb_mprotect(PROT_NONE)` and only then added the record.
- Disarming: `pb_disarm_range`, reached from any `mprotect` overlapping the range, deleted the record while the page was still `PROT_NONE`, and the real `mprotect` had not run yet.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. The shipped order violates `Safe` with `ProtNoneUnrecorded` then `Read` and `dead = TRUE`. Recording first, `armFirst = TRUE`, holds.

Reproduced on both arches with one thread re-arming in a loop and one thread reading: `SIGSEGV` in 4 of 5 runs on x86 `6.8.0-101-generic` and 4 of 5 on arm64 `6.6.62+rpt-rpi-v8`. As a suite case, `extra armrace` failed 5 of 15 before the fix and 0 of 15 after.

Fix, in three parts:

Fix, in three parts.

- `pb_armed_claim` inserts the record under `marea_lock` before the page is made inaccessible, and `pb_armed_unclaim` removes it again if the `mprotect` fails. The record now outlives the protection it explains, in the arm direction.
- `pb_disarm_range` restores each page to its saved protection first and deletes the records in a second pass, so the reverse also never leaves an unowned `PROT_NONE` page.
- `pb_handle_data` is convergent. With no record it asks `pb_page_satisfies` whether the faulting access is already legal, which is what a racing thread's restore or remap leaves behind. Legal means swallow, otherwise deliver the signal. This also stops a fault that was already resolved from turning into a crash.

A note on the count: `armrace` sometimes reports two trace lines and that is correct. The reloader advances the handler epoch on each `mprotect`, and the module promises one dump per handler epoch, so a second epoch legitimately dumps again. The defect is the crash, not the count.

## Unloading the module stranded pages it had made inaccessible

`data=` works by making a page `PROT_NONE`, and the only thing that can turn it back is this module's own fault handler, running inside the target process. `fh_exit` freed the records and restored nothing, and it could not: `module_exit` runs in the process doing the removal, and `mprotect` only affects the caller's address space. So after `rmmod`, a process holding an armed page took `SIGSEGV` on its next access to that address, a signal the module had caused itself.

Reproduced on x86 `6.8.0-101-generic` with a `mkfifo` gate so the read happens only after the module is confirmed gone: the page is `---p` in `/proc/self/maps` while loaded, `rmmod` returns 0 with `refcnt 0` and `unloaded` in `dmesg`, the page is still `---p`, and the read faults. The target can rescue the page with its own `mprotect`, so this is an unhandled signal, not lost data and not an unrecoverable process. Not reproduced on arm64.

Getting this wrong cost real time. The first several attempts concluded the opposite, that the page was fine after unload, and the reason was the harness: the child did `open()` on a gate file that did not exist yet, so the open failed, the wait was skipped, and the read happened while the module was still loaded, where the module correctly restored the page. Use a FIFO and block on `read()`; a plain file is not a gate. The test must also confirm the module is really gone, with `lsmod` and `dmesg`, before the read.

Fix: while any armed record still describes a page that is `PROT_NONE`, the module holds a reference to itself, so `rmmod` returns `-EBUSY` and the fault handler stays available. Three deliberate choices:

- State is a per-record `restored` flag, not a counter. A counter leaks in two opposite directions: too high and the module is never removable, too low and this stranding bug returns silently. The first version of the work item leaked permanently by leaving the queued flag set when it found a page still inaccessible, so no later release could ever be queued, and clearing the Pi needed a reboot. arm64 caught that on the first run.
- The reference is dropped from a work item, never from a hook. If the last `module_put` ran inside the fault handler, `module_exit` would execute on the fault path, call `pb_remove_hooks`, and free the module text the handler is still running in.
- The pin is taken before `PROT_NONE` is set, so there is never an instant where a page is inaccessible and the module is removable.

Modelled locally, listed in `AGENTS.md`: `hookdrop` violates `NoStrand`, `leak` violates `NoLeak`, and the shipped configuration holds both. `extra pin` asserts `rmmod` is refused while a page is held and `extra pinoff` asserts it is permitted after a read. Both suites pass on x86 and arm64.

One accepted cost: the release is asynchronous, so `rmmod` can be refused for a moment after the last armed page has gone. Scripts that remove the module immediately after a target exits may need to retry. That is the price of not dropping the reference from a hook.

## `mremap` moved an armed page into a window with no record

`fh_sys_mremap` called `real_sys_mremap` first, so the kernel moved the page while it was still `PROT_NONE`, and only afterwards did `pb_note_mremap` move the armed record. In between, the page sat at its new address, inaccessible, with the record still filed under the old one. `pb_handle_data` found nothing, and the reader took a real `SIGSEGV`.

The settle step had the mirror-image defect: for a destination outside the armed range it deleted the record and only then restored the protection, so it also left an inaccessible page with no record.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. The shipped order violates `Safe` with `MovePage` then `Read` and `dead = TRUE`; moving the record first, `moveRecordFirst = TRUE`, holds.

Reproduced with a reader spinning on a destination that is kept mapped by a shadow page, so a fault there can only be the module's. 8 of 8 failures on x86, and the control without the module survived 3 of 3.

Fix, in three parts:

- A page we armed is ours wherever it now lives, so `pb_handle_data` consults the record before the range test. A moved page can legitimately sit outside `data=`, and the record is what says it is ours.
- `MREMAP_FIXED` names the destination before the syscall. A page whose destination stays in range has its record relocated ahead of the move, and moved back if the syscall fails. A page whose destination leaves the range is released by `pb_release_armed`, which restores the protection and only then drops the record, so it arrives accessible and needs no record.
- The same restore-before-forget order as `pb_disarm_range`.

`extra mremaprace` covers it. It failed 8 of 8 before the fix and 0 of 25 after, with both suites passing on x86 and arm64.

Still open, and it needs its own test: `mremap` without `MREMAP_FIXED` still has the window. The kernel picks the destination, so the record cannot be placed ahead of the move. Only the record can be consulted afterwards, which is too late for a reader that already faulted.

## Note on the `MREMAP_MAYMOVE` window above, not a separate bug

The entry above calls the non-`FIXED` window open. That is right about the ordering and wrong about how often it can bite, and the difference is worth recording.

Measured on 6.8.0-101-generic: a same-size `MREMAP_MAYMOVE` does not move anything. Every page tested came back at its original address, so the record was never misplaced and there is no window at all. A move only happens when the size changes and the neighbouring pages are occupied; that case does relocate, into the mmap area.

So no crash was reproduced. Two attempts failed and both are recorded rather than quietly dropped. Forcing a relocation and scanning the whole mmap region from a second thread, with a signal handler that tells a module-caused fault apart from a fault on a plain unmapped address, produced no failure with or without the module. The window is real in the ordering but too narrow to hit from user space.

Hardening, not a bug fix: when `MREMAP_FIXED` is absent and `old_len != new_len`, the armed pages are released before the syscall, so they arrive accessible and need no record. The same-size case is left alone, because releasing there would drop arming for a call that does not move anything. The size-change guard is empirical, taken from the measurement above on this kernel; a kernel that relocates on a same-size move would need the guard widened. The cost when it does fire is that a relocated page is not re-armed until the next executable `mprotect`. Both suites pass on x86 and arm64.

Do not count this as a confirmed bug. It has no reproduction.

A third attempt failed too, and the reason is worth keeping because it closes the question rather than leaving it open. The reader has to be sitting on the destination at the moment the window opens, and the destination is never knowable in advance:

- A sweep is useless. It spends its time faulting over addresses nothing is mapped at, while all the moves complete in microseconds, so it never overlaps the window.
- The destinations look like they step down by a constant stride, so predicting the next one looks attractive. It is not reliable: the gap varies, and a prediction check caught the kernel choosing a different address at the third move.
- Hammering the recently used destinations fails because the kernel always places the next one at a new, lower address, never a repeat. No previously used address is ever the next destination.

With the hardening deliberately disabled, the test still reported zero hits. So on this kernel the window is below what a user space test can reach. That is a stronger statement than "we failed to find a test", and it means the honest conclusion is that the hardening is unfalsifiable by test here rather than merely untested.

What replaced the missing test is a check of the assumption the guard actually rests on. `extra maymove` now asserts that a same-size `MREMAP_MAYMOVE` does not relocate, and fails with a clear message if it ever does, because that is exactly the condition under which `fh_sys_mremap` stops releasing pages and the window reopens. It passes on x86 and arm64. The guard is now tied to a checked premise rather than to a comment.
## Holding `marea_lock` across `mprotect` deadlocked against the mmap hook

Two paths took the two locks in opposite orders.

- `fh_vm_mmap_pgoff` is an internal kernel hook. The kernel calls it with `mmap_write_lock` already held, and the hook calls `pb_drop_user_range`, which takes `marea_lock`. So `mmap_write_lock` is held while `marea_lock` is wanted.
- `pb_disarm_range`, `pb_armed_after_move` and `pb_release_armed` held `marea_lock` across `pb_mprotect`, which reaches the real mprotect and wants `mmap_write_lock`. So `marea_lock` was held while `mmap_write_lock` was wanted.

That is ABBA. One thread in the restore path and one thread in a plain `mmap` deadlocks, with the two locks held and both waits outstanding.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. `heldLock = FALSE`, the shipped nesting, violates `Safe` with A holding `marea` waiting for `mmap` and B holding `mmap` waiting for `marea`. `heldLock = TRUE` holds.

The suite did not catch this. No case in 47 deadlocked, because the interleaving needs one thread restoring while another maps.

Fix: no path holds `marea_lock` across `pb_mprotect` any more. Each of the three collects the record under the lock, restores with the lock released, then drops the record. The record still outlives the restore, so a reader that faults in that gap finds one and is handled, and a restore that lands on a page a reader already fixed is the same protection. Both suites pass.

## A data page is only ever traced once, not once per handler epoch

Not a crash, and not fixed. The contract in `README.md` and in the fix for "a data read was logged on every fault" says one dump per handler epoch. The code does one per data page, for the life of the process.

A read fault restores the page but leaves the armed record in place, so `pb_arm_range` skips it for ever. The page stays readable, no later read faults, the hook is never entered, and no trace line is written at any later epoch. Only a `munmap`, a replacing `mmap` or an `mprotect` over the data page clears the record.

Measured on x86 `6.8.0-101-generic`: arm, read once, re-`mprotect` the code page so it is dumped again and its epoch advances, read the same address. One trace line, not two. Clean trace and module unloaded, zero lines.

Modelled in a TLA+ spec kept locally and not committed; see `AGENTS.md`. The shipped behaviour violates the property on Arm, Read, AdvanceEpoch, ReadStale; re-arming on epoch change holds.

Left unfixed on purpose. Re-arming a stale record costs a fault per bytecode read rather than one per page, and every re-arm reintroduces the arming-window class of bug that caused the earlier `SIGSEGV` fixes. The decision and the options are documented in `AGENTS.md`.

## Double validation of the fixes above, not a bug

Each of these was run twice on the pre-fix module (`5257f3a`) and twice on the fixed module, on both x86 `6.8.0-101-generic` and arm64 `6.6.62+rpt-rpi-v8`.

| Case | Bug, twice | Fix, twice |
|---|---|---|
| `exact=1` | `path=extr` still tracked (`epoch` exit 0) | miss, then `path=extra` exit 0 |
| `fork` | `forkread` exit 1 | exit 0 |
| read-only arm | `roarm` exit 1 | exit 0 |
| `mremap` | `moveread` exit 1 | exit 0 outside the range, and again inside `260000000-280000000` |
| non-matching exec | `stale` exit 142 | exit 139 |

The trace-line bug and the arm-once flag were fixed from inspection. `extra read` passed twice on the fixed module on both arches. Their original failure mode was not replayed as its own double run.
