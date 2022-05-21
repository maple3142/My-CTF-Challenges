all:
	nasm -f elf64 -o vuln.o vuln.S
	ld -o vuln vuln.o
	strip vuln
clean:
	rm vuln.o
	rm vuln
