import struct, os, sys

filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "LinYuDriverLoader4.9.sh")
filepath2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "LinYuKernelNrc1.6.sh")

def triage_elf(path):
    print(f"\n{'='*60}")
    print(f"FILE: {os.path.basename(path)}")
    print(f"SIZE: {os.path.getsize(path)} bytes")
    print(f"{'='*60}")
    
    with open(path, 'rb') as f:
        data = f.read()
    
    # ELF Header
    magic = data[:4]
    if magic != b'\x7fELF':
        print("NOT AN ELF FILE!")
        return
    
    ei_class = data[4]  # 1=32bit, 2=64bit
    ei_data = data[5]   # 1=LE, 2=BE
    e_type = struct.unpack_from('<H', data, 16)[0]
    e_machine = struct.unpack_from('<H', data, 18)[0]
    e_entry = struct.unpack_from('<Q', data, 24)[0]
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    
    print(f"Class: {'64-bit' if ei_class==2 else '32-bit'}")
    print(f"Endian: {'Little' if ei_data==1 else 'Big'}")
    print(f"Type: {e_type} ({'EXEC' if e_type==2 else 'DYN' if e_type==3 else 'OTHER'})")
    print(f"Machine: {e_machine} ({'AARCH64' if e_machine==183 else 'x86_64' if e_machine==62 else 'OTHER'})")
    print(f"Entry: 0x{e_entry:x}")
    print(f"PHOFF: 0x{e_phoff:x}, PHNUM: {e_phnum}, PHENTSIZE: {e_phentsize}")
    print(f"SHOFF: 0x{e_shoff:x}, SHNUM: {e_shnum}")
    
    # Program Headers
    print(f"\nProgram Headers:")
    for i in range(min(e_phnum, 5)):  # limit to 5 to avoid garbage
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            print(f"  [{i}] TRUNCATED")
            break
        p_type = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off+4)[0]
        p_offset = struct.unpack_from('<Q', data, off+8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off+16)[0]
        p_filesz = struct.unpack_from('<Q', data, off+32)[0]
        p_memsz = struct.unpack_from('<Q', data, off+40)[0]
        
        type_str = {1:'LOAD', 2:'DYNAMIC', 3:'INTERP', 4:'NOTE', 6:'PHDR'}.get(p_type, f'0x{p_type:08x}')
        flags_str = ('R' if p_flags&4 else '-') + ('W' if p_flags&2 else '-') + ('X' if p_flags&1 else '-')
        print(f"  [{i}] {type_str:12s} {flags_str} offset=0x{p_offset:x} vaddr=0x{p_vaddr:x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x}")
    
    # Strings extraction (last 2KB for build metadata)
    print(f"\nBuild metadata (last 1024 bytes strings):")
    tail = data[-1024:]
    strings = []
    current = b''
    for b in tail:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= 8:
                strings.append(current.decode('ascii', errors='ignore'))
            current = b''
    if len(current) >= 8:
        strings.append(current.decode('ascii', errors='ignore'))
    for s in strings[:20]:
        print(f"  {s}")
    
    # Entry point area
    if e_type == 2:  # EXEC
        # For this binary, code is at vaddr 0x330000, file offset = vaddr - 0x330000
        # Try to find the code segment
        for i in range(min(e_phnum, 3)):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, off)[0]
            p_flags = struct.unpack_from('<I', data, off+4)[0]
            p_offset = struct.unpack_from('<Q', data, off+8)[0]
            p_vaddr = struct.unpack_from('<Q', data, off+16)[0]
            p_filesz = struct.unpack_from('<Q', data, off+32)[0]
            if p_type == 1 and (p_flags & 1):  # LOAD + X
                entry_file_offset = e_entry - p_vaddr + p_offset
                print(f"\nEntry point file offset: 0x{entry_file_offset:x}")
                print(f"First 32 bytes at entry:")
                entry_bytes = data[entry_file_offset:entry_file_offset+32]
                print(f"  {entry_bytes.hex()}")
                break

for p in [filepath, filepath2]:
    if os.path.exists(p):
        triage_elf(p)
    else:
        print(f"NOT FOUND: {p}")
