ar = [
    35457810,
    990774802,
    132637,
    939787282,
    34148153,
    386730044,
    755696188,
    956894252,
    302714898,
    437067070,
    470025275,
    503971899,
    1819241506,
]
x = int.from_bytes(b"ictf", "little")
for y in ar:
    z = x.to_bytes(4, "little")
    print(z.decode(), end="")
    x ^= y
z = x.to_bytes(4, "little")
print(z.decode(), end="")
