ar = [
    3850171132014162800,
    5340012885551996783,
    7570249252805341466,
    15654706945287115546,
    3351868198033773624,
]

a = 414158692984894407
b = 11976572118272491985
m = 1 << 64


def rev(x):
    return (x - b) * pow(a, -1, m) % m


for x in ar:
    print(rev(x).to_bytes(8, "little").decode(), end="", flush=True)