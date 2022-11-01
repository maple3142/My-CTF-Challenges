#!/usr/bin/env python3
from tempfile import TemporaryDirectory
import os

tmpl = """
// Author: %s
class HelloWorld {
    public static void main(String[] args){
        System.out.println("Hello, World!");
    }
}
"""

with TemporaryDirectory() as td:
    os.chdir(td)
    name = input("Name: ")
    if not name.isprintable():
        print("Invalid name")
        exit(0)
    with open("HelloWorld.java", "w") as f:
        f.write(tmpl % name)
    os.system("javac HelloWorld.java")
    os.system("java HelloWorld")
