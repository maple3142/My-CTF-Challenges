import random

flag = b"ictf{do_you_know_this_flag_checker_doesnt_work_with_O2_because_compiler_may_optimize_it_to_return_zero_directly_https://godbolt.org/z/8nr9cjY4T}"

assert len(flag) % 8 == 0


def gen(x):
    # a*x+b=x
    # (a-1)*x+b=0
    # b=-(a-1)*x
    a = random.randrange(2**64) & ~1
    b = -(a - 1) * x % (2**64)
    return a, b


for i in range(0, len(flag), 8):
    a, b = gen(int.from_bytes(flag[i : i + 8], "little"))
    print("{%d, %d, %dull, %dull, %d}," % (i // 8, 1, a, b, 0))
