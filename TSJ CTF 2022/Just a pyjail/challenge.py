#!/usr/local/bin/python
import sys
import os


def wrapper(exit):
    def hook(event, args):
        for x in (
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
            "__new__",
        ):
            if x in (event + "".join(f"{x}" for x in args)).lower():
                exit(0)

    return hook


# read user input and disallow dangerous things
inp = input("Input: ")
try:
    inp.encode("ascii")
except UnicodeEncodeError:
    print("ASCII only pls!!!")
    exit()
if "__" in inp:
    print("No __ pls!!!")
    exit()

# compile it into code object
code = compile(inp, "<usercode>", "exec")

# just be extra safe that no one can escape
sys.addaudithook(wrapper(os._exit))

# run user code in a sandbox
exec(code, {"__builtins__": None})


print("Bye")
