def vokram(text, program):
    while True:
        for pat, repl, stop in program:
            if pat in text:
                text = text.replace(pat, repl, 1)
                if stop:
                    return text
                break
        else:
            return text


def parse(source):
    program = []
    for line in source.strip().splitlines():
        pat, repl = line.split(":", 1)
        stop = False
        if len(repl) > 0 and repl[0] == ":":
            repl = repl[1:]
            stop = True
        if ":" in repl:
            raise ValueError("invalid rule: %r" % line)
        program.append((pat, repl, stop))
    return program


def stringify(rules):
    ret = ""
    for pat, repl, stop in rules:
        ret += pat
        ret += "::" if stop else ":"
        ret += repl
        ret += "\n"
    return ret


def base(v, n, ln):
    ret = []
    for i in range(ln):
        ret.append(v % n)
        v //= n
    ret.reverse()
    return ret


import random
import emoji
import grapheme

emojis = (
    [c for c in emoji.EMOJI_DATA.keys() if len(c) <= 1]
    + [chr(x) for x in range(0x3040, 0x309F + 1)]
    + [chr(x) for x in range(0x30A0, 0x30FF + 1)]
)
print(len(emojis))
# for e in emojis:
#     print(e, )
#     assert len(list(grapheme.graphemes(e))) == 1
# exit()

chars = {}
used = {}
rnd = random.Random(133337)


def mapchr(x):
    # return chr(((3 * x) ^ 137) + 128147)
    if x in chars:
        return chars[x]
    while True:
        c = rnd.choice(emojis)
        if c not in used:
            break
    chars[x] = c
    used[c] = True
    return c


flag = "ictf{lfsr_4nd_m4rk0v_alg0r17hm_mao.snuke.org}"

program = []

import string

chrs = string.ascii_letters + "{_}!@#$%^&*()_." + string.digits
basecvt = mapchr(3142)
tmp_program = []
for c in chrs:
    b = base(ord(c), 3, 5)
    s = "".join(map(mapchr, b))
    tmp_program.append((basecvt + c, s + basecvt, False))
random.shuffle(tmp_program)
program.extend(tmp_program)
program.append((basecvt, "", False))


lfsr_base = 10000
ln = len(flag) * 5
print("ln", ln)
rnd2 = random.Random(878787)
taps = [0] + [i for i in range(1, ln) if rnd2.random() < 0.3]
print("taps", taps)
tmp_program = []
for i in range(ln):
    ch = mapchr(lfsr_base + i)
    ch_next = mapchr(lfsr_base + i + 1)
    for reg in (0, 1, 2):
        for eat in (0, 1, 2):
            pat = ch + mapchr(reg) + mapchr(eat)
            cal = (reg + eat) % 3 if i in taps else reg
            if i > 0:
                repl = mapchr(eat) + ch_next + mapchr(cal)
            else:
                repl = ch_next + mapchr(cal)
            tmp_program.append((pat, repl, False))
random.shuffle(tmp_program)
program.extend(tmp_program)
program.append((mapchr(lfsr_base + ln), "", False))

loop = 1337

state = sum([base(ord(c), 3, 5) for c in flag], [])
print("init", state)
for _ in range(loop):
    state = state[1:] + [sum([state[i] for i in taps]) % 3]
final = "".join(map(str, state))
print("res", final)
final2 = "".join(map(mapchr, state))

loop_base = 48763
tmp_program = []
for i in range(loop + 1):
    if i != loop:
        tmp_program.append(
            (
                mapchr(loop_base + i),
                mapchr(loop_base + i + 1) + mapchr(lfsr_base) + mapchr(0),
                False,
            )
        )
    else:
        random.shuffle(tmp_program)
        program.extend(tmp_program)
        # if correct
        program.append((mapchr(loop_base + i) + final2, "Correct", True))
        # cleanup if wrong
        program.append(
            (mapchr(loop_base + i) + mapchr(0), mapchr(loop_base + i), False)
        )
        program.append(
            (mapchr(loop_base + i) + mapchr(1), mapchr(loop_base + i), False)
        )
        program.append(
            (mapchr(loop_base + i) + mapchr(2), mapchr(loop_base + i), False)
        )
        program.append((mapchr(loop_base + i), "Wrong", True))

# init rule
program.append(("", mapchr(loop_base) + basecvt, False))


with open("check_flag.vokram", "w") as f:
    f.write(stringify(program))
print("generate done")

# print("out", vokram(flag, program))
# print("out", vokram(flag[:-1] + "x", program))
