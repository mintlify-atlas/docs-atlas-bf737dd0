import struct, hashlib, zlib, os

WS = '/home/daytona/workspace'
GD = WS + '/.git'
IDX = GD + '/index'

def read_index(data):
    n = struct.unpack('>I', data[8:12])[0]
    pos = 12
    entries = []
    for _ in range(n):
        estart = pos
        fields = struct.unpack('>10I', data[pos:pos+40])
        pos += 40
        sha1 = data[pos:pos+20]
        pos += 20
        flags = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2
        stage = (flags >> 12) & 0x3
        name_end = pos
        while data[name_end] != 0:
            name_end += 1
        name = data[pos:name_end].decode('utf-8', errors='replace')
        # total so far from estart: 40+20+2+len(name)+1 = 63+len(name)
        cur_len = 63 + len(name.encode('utf-8'))
        padded = ((cur_len + 7) // 8) * 8
        pos = estart + padded
        entries.append({'fields': fields, 'sha1': sha1, 'flags': flags, 'stage': stage, 'name': name, 'raw': bytes(data[estart:pos])})
    return entries, pos

def hash_blob(fp):
    with open(fp, 'rb') as f:
        content = f.read()
    hdr = ('blob ' + str(len(content)) + '\0').encode()
    full = hdr + content
    sha = hashlib.sha1(full).hexdigest()
    odir = GD + '/objects/' + sha[:2]
    opath = odir + '/' + sha[2:]
    os.makedirs(odir, exist_ok=True)
    if not os.path.exists(opath):
        with open(opath, 'wb') as fh:
            fh.write(zlib.compress(full, 1))
    return bytes.fromhex(sha)

def build_entry(fp, sha1_bytes, stage=0):
    rel = os.path.relpath(fp, WS)
    s = os.stat(fp)
    cs = int(s.st_ctime); cn = 0
    ms = int(s.st_mtime); mn = 0
    dev = s.st_dev & 0xFFFFFFFF
    ino = s.st_ino & 0xFFFFFFFF
    mode = 0o100644
    uid = s.st_uid; gid = s.st_gid; sz = s.st_size
    name_b = rel.encode('utf-8')
    name_len = len(name_b) & 0xFFF
    flags = (stage << 12) | name_len
    e = struct.pack('>10I', cs, cn, ms, mn, dev, ino, mode, uid, gid, sz)
    e += sha1_bytes
    e += struct.pack('>H', flags)
    e += name_b + b'\x00'
    cur_len = 63 + len(name_b)
    target = ((cur_len + 7) // 8) * 8
    e += b'\x00' * (target - cur_len)
    return e

with open(IDX, 'rb') as f:
    data = bytearray(f.read())

ver = struct.unpack('>I', data[4:8])[0]
entries, ext_start = read_index(data)

print('Parsed', len(entries), 'entries')
conflict_files = {'docs.json', 'index.mdx', 'quickstart.mdx'}
new_entries = []
seen = set()
for e in entries:
    nm = e['name']
    if nm in conflict_files:
        if nm not in seen:
            seen.add(nm)
            fp = WS + '/' + nm
            sha = hash_blob(fp)
            raw = build_entry(fp, sha, stage=0)
            new_entries.append((0, nm, raw))
            print('Rebuilt:', nm, '->', sha.hex())
    else:
        new_entries.append((e['stage'], nm, e['raw']))

new_entries.sort(key=lambda x: x[1])

idx = bytearray(b'DIRC')
idx += struct.pack('>I', ver)
idx += struct.pack('>I', len(new_entries))
for s2, n2, r2 in new_entries:
    idx += r2

idx += data[ext_start:-20]
idx += hashlib.sha1(idx).digest()

with open(IDX, 'wb') as fh:
    fh.write(idx)

print('Written index:', len(new_entries), 'entries')
