#!/usr/bin/env python3
from base64 import b64decode
from tempfile import TemporaryDirectory
import tarfile, subprocess
from pathlib import Path


def check_tar(tar):
    for member in tar.getmembers():
        if not member.isfile():  # only files are allowed
            return False
        if "flag.txt" in member.name:  # no flag.txt allowed
            return False
    return True


if __name__ == "__main__":

    with TemporaryDirectory() as tmpdir:
        tarbin = b64decode(input("Enter a base64 encoded tar: "))
        uploadTar = Path(tmpdir) / "upload.tar"
        uploadTar.write_bytes(tarbin)

        with tarfile.open(uploadTar, "r:") as tar:
            if not check_tar(tar):
                print("Invalid tar")
                exit(1)

        extractDir = Path(tmpdir) / "extract"
        extractDir.mkdir()
        subprocess.run(
            ["tar", "-xf", uploadTar, "-C", extractDir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        print("Extracted files:")
        for f in extractDir.iterdir():
            print(f.name)

        flag = extractDir / "flag.txt"
        if flag.exists():
            print(flag.read_text())
