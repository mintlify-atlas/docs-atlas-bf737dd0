import struct, hashlib, zlib, os

WS = '/home/daytona/workspace'
GD = WS + '/.git'
IDX = GD + '/index'

# All files to track (relative to WS), sorted
ALL_FILES = sorted([
    '.atlas-analysis.json',
    '.mintignore',
    'AGENTS.md',
    'LICENSE',
    'README.md',
    'admin/deployment.mdx',
    'admin/security.mdx',
    'admin/users.mdx',
    'api/authentication.mdx',
    'api/endpoints/analysis.mdx',
    'api/endpoints/budgets.mdx',
    'api/endpoints/finances.mdx',
    'api/endpoints/projects.mdx',
    'api/endpoints/users.mdx',
    'api/overview.mdx',
    'configuration.mdx',
    'docs.json',
    'favicon.svg',
    'features/analysis.mdx',
    'features/budgets.mdx',
    'features/finances.mdx',
    'features/projects.mdx',
    'index.mdx',
    'introduction.mdx',
    'logo/dark.svg',
    'logo/light.svg',
    'quickstart.mdx',
])

def hash_blob(rel_path):
    fp = WS + '/' + rel_path
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

def build_entry(rel_path, sha1_bytes, stage=0):
    fp = WS + '/' + rel_path
    s = os.stat(fp)
    cs = int(s.st_ctime); cn = 0
    ms = int(s.st_mtime); mn = 0
    dev = s.st_dev & 0xFFFFFFFF
    ino = s.st_ino & 0xFFFFFFFF
    mode = 0o100644
    uid = s.st_uid; gid = s.st_gid; sz = s.st_size
    name_b = rel_path.encode('utf-8')
    name_len = len(name_b) & 0xFFF
    flags = (stage << 12) | name_len
    e = struct.pack('>10I', cs, cn, ms, mn, dev, ino, mode, uid, gid, sz)
    e += sha1_bytes
    e += struct.pack('>H', flags)
    e += name_b + b'\x00'
    # pad to 8-byte boundary: fixed=62, name+null = len(name_b)+1, total = 63+len(name_b)
    cur_len = 63 + len(name_b)
    target = ((cur_len + 7) // 8) * 8
    e += b'\x00' * (target - cur_len)
    return e

entries = []
for rel in ALL_FILES:
    fp = WS + '/' + rel
    if os.path.isfile(fp):
        sha = hash_blob(rel)
        raw = build_entry(rel, sha, stage=0)
        entries.append((rel, raw))
        print('Added:', rel)
    else:
        print('MISSING:', rel)

# Build index (no extensions)
idx = bytearray(b'DIRC')
idx += struct.pack('>I', 2)  # version 2
idx += struct.pack('>I', len(entries))
for rel, raw in entries:
    idx += raw
# Add SHA1 checksum (no extensions)
idx += hashlib.sha1(idx).digest()

with open(IDX, 'wb') as fh:
    fh.write(idx)

print('Written fresh index with', len(entries), 'entries, size', len(idx), 'bytes')
