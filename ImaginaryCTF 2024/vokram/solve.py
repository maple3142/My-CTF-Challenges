maps = {"🥽": "0", "🔼": "1", "🦥": "2"}

with open("check_flag.vokram") as f:
    source = f.read()

with open("processed.vokram", "w") as f:
    for c in list(source):
        f.write(maps.get(c, c))


def split(s):
    return list(s)


with open("processed.vokram") as f:
    source = f.read()
    rules = {
        tuple(split(x)): tuple(split(y))
        for x, y in [
            line.split("::") if "::" in line else line.split(":")
            for line in source.strip().splitlines()
        ]
    }

cnt = 0
st = rules[()][:1]
while st in rules:
    cnt += 1
    st = rules[st][:1]
cnt -= 1
print("lfsr cnt", cnt)

taps = []
sym = rules[rules[()][:1]][1]
i = 0
while True:
    tbl = {k: v for k, v in rules.items() if sym in k}
    print(sym, tbl)
    if len(tbl) != 9:
        break
    tbl2 = {
        tuple(x for x in k if x in ("0", "1", "2")): tuple(
            x for x in v if x in ("0", "1", "2")
        )
        for k, v in tbl.items()
    }
    if tbl2[("1", "2")][-1] == "0":
        print(i, "is add")
        taps.append(i)
    elif tbl2[("1", "2")][-1] == "1":
        print(i, "not add")
    else:
        raise ValueError("invalid")
    nxt_sym = list(tbl.values())[0][0] if i == 0 else list(tbl.values())[0][1]
    sym = nxt_sym
    i += 1
print(taps)

state = [k for k, v in rules.items() if v == tuple("Correct")][0][1:]
state = list(map(int, state))
for _ in range(cnt):
    out = state[-1]
    first = (out - sum([state[i - 1] for i in taps[1:]])) % 3
    state = [first] + state[:-1]

for i in range(0, len(state), 5):
    v = int("".join(map(str, state[i : i + 5])), 3)
    print(chr(v), end="")
print()
