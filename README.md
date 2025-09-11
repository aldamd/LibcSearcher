# LibcSearch
LibcSearch is a small utility to help in CTF `ret2libc` workflows: query online libc symbol databases by known symbol offsets, identify matching libc builds, inspect symbol offsets, and optionally download matching .so files.

## Purpose
Designed for CTF players performing remote `ret2libc` / libc-leak exploitation. Given a set of leaked symbol names and their addresses, LibcSearch finds candidate libc builds and exposes symbol offsets so you can compute libc base, target addresses (e.g. system), /bin/sh location, etc..

## Requirements
- Python 3.8+
- requests

## Quick Usage
```python
from LibcSearch import LibcSearch

# symbol names and their leaked addresses (hex strings ok, may include 0x)
sym = ["puts", "gets", "binsh"]
addr = ["0x7f10101010"]

libsrch = LibcSearch(sym, addr)

# download relevant libc shared objects to the current working directory
libsrch.download()

# inspect candidates
for libc in srch.libc_list:
  print(libc)
```
### Results
```
[*]libc6-amd64_2.24-3ubuntu1_i386
    puts         0x69010
    gets         0x686e0
    str_bin_sh   0x161960
[*]libc-2.20-20.mga5.x86_64_2
    puts         0x62010
    gets         0x617e0
    str_bin_sh   0x1735a4
[*]libc6-amd64_2.30-7_i386
    puts         0x76010
    gets         0x755f0
    str_bin_sh   0x1881ac
[*]musl_1.1.19-2_amd64
    puts         0x5c050
    gets         0x25a20
    str_bin_sh   0xa5750
[*]libc6_2.28-0ubuntu1_amd64
    puts         0x81010
    gets         0x80730
    str_bin_sh   0x1aae80
[*]libc-2.32-8.mga8.i586
    puts         0xf2680
    gets         0x311f0
    str_bin_sh   0x152e3d
[*]libc-2.32-5.mga8.i586
    puts         0xf2660
    gets         0x311f0
    str_bin_sh   0x152e3d
[*]libc-2.35.9000-29.fc37.x86_64
    puts         0x10f670
    gets         0x36dd0
    str_bin_sh   0x192011
```
