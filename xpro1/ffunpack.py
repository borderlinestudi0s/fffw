#!/usr/bin/env python3
"""
Offline unpacker for Fujifilm X-series .DAT firmware (fflz segments).

Faithful Python port of tiredboffin/fffw ffcompress/fflz decompressor.go.
Locates fflz segments by their self-describing 20-byte header, decompresses
each, and verifies the decoded size against the header. No camera involved.

Usage: python3 -I ffunpack.py <FPUPDATE.DAT> <out_dir>
"""
import sys, struct, os, math
from collections import Counter

PAGE_SIZE      = 16384
WINDOW_SIZE    = 2048
WINDOW_MASK    = WINDOW_SIZE - 1
READ_BUF_SIZE  = WINDOW_SIZE * 16   # 32768
HEADER_SIZE    = 20

def num_pages(size): return (size + PAGE_SIZE - 1) // PAGE_SIZE

def valid_header(usize, psize, npages, pgsize, align):
    return (psize != 0 and usize != 0 and psize < usize
            and pgsize == PAGE_SIZE and num_pages(psize) == npages and align == 4)

def unpack_fflz(packed: bytes) -> bytes:
    """packed = 20-byte header + token stream (PackedSize counts the header)."""
    usize, psize, npages, pgsize, align = struct.unpack_from("<5I", packed, 0)
    if not valid_header(usize, psize, npages, pgsize, align):
        raise ValueError("invalid header")
    buf = bytearray(READ_BUF_SIZE)
    epos = 0
    rp = HEADER_SIZE          # read pointer into packed
    read_count = HEADER_SIZE  # bytes consumed from packed (incl. header)
    written = 0
    out = bytearray()
    while read_count < psize:
        b0 = packed[rp]; rp += 1; read_count += 1
        if b0 & 0x80 == 0:                 # literal run
            length = b0; offset = 0
        else:                              # back-reference
            b1 = packed[rp]; rp += 1; read_count += 1
            length = b1 & 0x0f
            offset = ((b0 & 0x7f) << 4 | (b1 >> 4)) & WINDOW_MASK
            if not (length != 0 and length <= offset):
                raise ValueError("bad match token (len==0 or len>offset)")
        if epos > READ_BUF_SIZE - length:  # slide window
            buf[0:WINDOW_SIZE] = buf[epos-WINDOW_SIZE:epos]
            epos = WINDOW_SIZE
        if offset > 0:                     # copy match (offset>=length => no overlap)
            buf[epos:epos+length] = buf[epos-offset:epos-offset+length]
        else:                              # copy literal bytes from input
            buf[epos:epos+length] = packed[rp:rp+length]; rp += length; read_count += length
        out += buf[epos:epos+length]
        written += length
        epos += length
    short = usize - written
    if 0 < short <= 127 and read_count == psize and psize % PAGE_SIZE == 0:
        out += b"\x00" * short; written += short   # restore packer's dropped final zero run
    if written != usize:
        raise ValueError(f"size mismatch: header says {usize}, decoded {written}")
    return bytes(out)

def find_fflz_headers(image: bytes):
    """Return list of (offset, usize, psize, npages) for every valid fflz header."""
    sig = struct.pack("<II", PAGE_SIZE, 4)   # pgsize, align => b'\x00\x40\x00\x00\x04\x00\x00\x00'
    hits = []
    s = 0
    while True:
        p = image.find(sig, s)
        if p < 0: break
        s = p + 1
        h = p - 12                            # header starts 12 bytes before the pgsize field
        if h < 0 or h + HEADER_SIZE > len(image): continue
        usize, psize, npages, pgsize, align = struct.unpack_from("<5I", image, h)
        if valid_header(usize, psize, npages, pgsize, align) and h + psize <= len(image):
            hits.append((h, usize, psize, npages))
    return hits

def entropy(b):
    if not b: return 0.0
    c = Counter(b)
    return -sum((n/len(b))*math.log2(n/len(b)) for n in c.values())

def peek(b, n=400):
    import re
    runs = re.findall(rb"[\x20-\x7e]{5,}", b)
    runs.sort(key=len, reverse=True)
    return [r.decode("latin1") for r in runs[:12]]

def main():
    dat_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    data = open(dat_path, "rb").read()
    inv  = bytes((~b) & 0xff for b in data)
    print(f"DAT: {dat_path}  size={len(data)}")
    for tag, image in (("raw", data), ("inverted", inv)):
        hits = find_fflz_headers(image)
        print(f"\n=== {tag} image: {len(hits)} valid fflz header(s) ===")
        if not hits: continue
        for (h, usize, psize, npages) in hits:
            print(f"  @ {h:#010x}  packed={psize:>10}  unpacked={usize:>10}  pages={npages}")
        # decompress all segments found in this orientation
        total = 0
        for i, (h, usize, psize, npages) in enumerate(hits):
            seg = image[h:h+psize]
            try:
                dec = unpack_fflz(seg)
            except Exception as e:
                print(f"  !! segment @{h:#x} failed: {e}")
                continue
            name = f"{tag}_seg{i:02d}_{h:#010x}_u{len(dec)}.bin"
            open(os.path.join(out_dir, name), "wb").write(dec)
            total += len(dec)
            print(f"  -> {name}  entropy={entropy(dec):.2f}")
            for ln in peek(dec)[:6]:
                print(f"       | {ln[:110]}")
        print(f"  decompressed total: {total} bytes across {len(hits)} segment(s)")

if __name__ == "__main__":
    main()
