#!/bin/bash
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
fail=0

say() { printf '\n===== %s =====\n' "$1"; }
mark() {
	if [ "$1" -eq 0 ]; then
		echo "PASS $2"
	else
		echo "FAIL $2"
		fail=1
	fi
}

sudo rmmod pagedrop 2>/dev/null || true
make clean >/dev/null
make
gcc -O0 -Wall -o userland/c/capture userland/c/capture.c -pthread
gcc -O0 -o userland/c/sigsegv.out userland/c/sigsegv.c
gcc -O0 -o userland/c/simple userland/c/simple.c
gcc -O0 -Wall -o userland/c/extra userland/c/extra.c
gcc -static -no-pie -O0 -o /tmp/upxtest.orig userland/c/upxtest.c
rm -f /tmp/upxtest
upx -q -o /tmp/upxtest /tmp/upxtest.orig
gcc -O0 -o /tmp/pb_check tools/x86/pb_check.c
gcc -O0 -o /tmp/pb_addr tools/x86/pb_addr.c
python3 tools/test_pb_rank.py
mark $? pb_rank

say "hooks"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=simple
hooks=$(sudo dmesg | grep 'pagedrop: hooked' | tail -12)
echo "$hooks"
missing=0
for n in mprotect pkey_mprotect mremap vm_mmap_pgoff execve execveat fork vfork clone clone3 do_exit force_sig_fault; do
	echo "$hooks" | grep -q "$n" || { echo "missing hook $n"; missing=1; }
done
mark "$missing" "hooks"

say "simple"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
text=$(python3 - << 'PY'
import struct
data=open("userland/c/simple","rb").read()
e_shoff,=struct.unpack_from("<Q", data, 40)
entsize,shnum,shstr=struct.unpack_from("<HHH", data, 58)
def sh(i):
    return struct.unpack_from("<IIQQQQIIQQ", data, e_shoff+i*entsize)
soff=sh(shstr)[4]
for i in range(shnum):
    s=sh(i)
    name=data[soff+s[0]:].split(b"\0",1)[0]
    if name==b".text":
        print(data[s[4]:s[4]+16].hex())
        break
PY
)
sudo /tmp/pb_check "$text" ./userland/c/simple
mark "$?" "simple"

say "sigsegv"
sudo rmmod pagedrop
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=sigsegv
sudo /tmp/pb_check 31c048bbd19d9691d08c97ff ./userland/c/sigsegv.out
mark "$?" "sigsegv live"
python3 - << 'PY'
import glob
sc=bytes.fromhex("31c048bbd19d9691d08c97ff")
ok=any(sc in open(f,"rb").read() and open(f,"rb").read(16)==b"\x90"*16 for f in glob.glob("/tmp/100000000_*"))
print("sigsegv file", "ok" if ok else "BAD")
raise SystemExit(0 if ok else 1)
PY
mark "$?" "sigsegv file"

say "capture"
sudo rmmod pagedrop
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=capture
./userland/c/capture
mark "$?" "capture"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo /tmp/pb_addr ./userland/c/capture
mark "$?" "capture mremap"

say "epoch"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra epoch
mark "$?" "epoch"

say "flip"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra flip
mark "$?" "flip"

say "read"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra read
mark "$?" "read"

say "execfail"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
cp -f userland/c/extra /tmp/exectest
sudo insmod ./pagedrop.ko path=exectest
/tmp/exectest fail
mark "$?" "execfail"

say "execve"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
mkdir -p /tmp/pbmatch
cp -f userland/c/extra /tmp/pbmatch/notme
sudo insmod ./pagedrop.ko path=pbmatch
./userland/c/extra execve
mark "$?" "execve"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
./userland/c/extra execveat
mark "$?" "execveat"

say "upx"
sudo rmmod pagedrop
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=upxtest
/tmp/upxtest
sudo /tmp/pb_check 900f1f440000909048b81122334455667788 /tmp/upxtest
mark "$?" "upx"

oops=$(sudo dmesg | grep -E 'Oops|BUG:' | tail -3 || true)
if [ -n "$oops" ]; then
	echo "$oops"
	mark 1 "no oops"
else
	mark 0 "no oops"
fi
sudo rmmod pagedrop || mark 1 "rmmod"
if [ "$fail" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "SOME FAILED"
fi
exit "$fail"
