# Original, UPX, and VMProtect

This note compares three builds of the same plain C program, `userland/c/regress.c`, and what pagedrop's executable-page dumps look like under Ghidra. The program is a dynamic PIE. It is not static. `mix()` returns `(x * 17) ^ 0x5a5a`. `main` calls `mix(13)` and prints `regress-ok 1 23175` when the result is `0x5a87`.

```sh
gcc -O0 -o regress.orig userland/c/regress.c
upx -o regress.upx regress.orig
```

`regress.vmp` is `regress.orig` after VMProtect Ultimate 3.10.6 demo (build 2770). The protected file prints a demo watermark and then the same `regress-ok` line.

## What each file is

| File | Link | On disk | Runs |
|---|---|---|---|
| `regress.orig` | dynamic PIE | normal ELF, sections present | `regress-ok 1 23175` |
| `regress.upx` | UPX 4.2.2, statically linked stub | no section headers | `regress-ok 1 23175` |
| `regress.vmp` | dynamic PIE, stripped | no recovered `mix` bytes in the file | demo line, then `regress-ok 1 23175` |

`mix` in the original is ordinary compiler output. Multiply by 17 is `shl $4` plus `add`, then `xor $0x5a5a`:

```
1149: endbr64
114d: push %rbp
114e: mov  %rsp,%rbp
1151: mov  %edi,-0x4(%rbp)
1154: mov  -0x4(%rbp),%edx
1157: mov  %edx,%eax
1159: shl  $0x4,%eax
115c: add  %edx,%eax
115e: xor  $0x5a5a,%eax
1163: pop  %rbp
1164: ret
```

That byte string is in `regress.orig`. It is not present as a contiguous pattern in `regress.vmp`.

## Running under pagedrop

Each file was run with `insmod pagedrop.ko path=regress` on Ubuntu 24.04, kernel 6.8.0-101-generic. `path=regress` matches all three comm names.

| Binary | Exit | Dumps |
|---|---|---|
| `regress.orig` | 0 | 437 |
| `regress.upx` | 0 | 440 |
| `regress.vmp` | 0 | 1956 |

The extra VMProtect dumps are mostly `mmap` of executable pages (about 1600) plus `mprotect` (about 360). The plain and UPX runs stay near 440. pagedrop is recording the VM and the packer stub, not only `mix`.

An earlier static build, packed by the same protector, never reached `main`. It was killed with `SIGKILL` (exit 137) with the module unloaded. That failure is the protector stub writing into a read-execute image, not pagedrop. Use a normal dynamic binary.

## Ghidra

`regress.orig` decompiles straight back to the source:

```c
uint mix(int param_1)
{
  return param_1 * 0x11 ^ 0x5a5a;
}
```

`main` calls `mix(0xd)` and compares the result with `0x5a87`.

`regress.upx` decompiles as the unpacker entry only. `mix` is not a function in the packed image. After UPX restores the original pages, a dump of that text is the same code as `regress.orig`. The packed file is the hard view. The dump is the easy one.

`regress.vmp` does not contain the `mix` byte pattern. Ghidra sees imports (`mprotect`, `memcpy`, `puts`, C++ string helpers) and a pile of unnamed code. It does not recover `param_1 * 0x11 ^ 0x5a5a`.

One runtime dump does. Page `62378cde4000_1140` holds the original `endbr64` / `push %rbp` / `xor $0x5a5a` body. Loaded as a raw x86-64 page, Ghidra produces:

```c
uint mix(void)
{
  int unaff_EDI;
  return unaff_EDI * 0x11 ^ 0x5a5a;
}
```

Same function. The argument looks wrong only because the dump is not an ELF, so the decompiler does not see the caller's `edi`. The arithmetic is intact.

## Judgment

The dumps are easier to read than the packed files, and not easier than the original.

- Against UPX, pagedrop removes the packer. The unpacked page reads like `regress.orig`.
- Against this VMProtect demo build, pagedrop also recovers `mix`. The protector left that body in an executable page. Static analysis of `regress.vmp` does not. The cost is finding that page among 1956 dumps. `tools/pb_rank.py` is the filter for that. On this run it kept the payload tgid, dropped 975 pages (`libc` 393, `ld-linux` 43, `libstdc++` 328, executable `PT_LOAD` of `regress.vmp` 211), and left 524. The `mix` page is one of 359 `mprotect` pages whose bytes are not in the packed file. It ranks last in that tier because it is the earliest epoch, and a later epoch sorts first. It still ranks above every remaining `mmap`, including `libm` and `libgcc_s`, which this filter does not drop. The `0x5a5a` immediate finds it inside the tier.
- This does not mean a fully virtualized function would appear. If `mix` had been replaced by bytecode in non-executable memory, no executable dump would contain `param_1 * 0x11 ^ 0x5a5a`. The dispatcher and handler pages would. That is the remaining gap.
