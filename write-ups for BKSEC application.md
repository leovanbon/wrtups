
[[cs]]

## 1. [dungeon-in-1983](https://dreamhack.io/wargame/challenges/1212)

pp
In the .zip that Dream gave me, there are two binaries. A quick look showed that their decompiled pseudocode looks the same anyway so i'm just going to analyze the deploy/prob.

![](attachment/fb65d3cde764679e051b47eb7e06b0f5.png)
`FUN_00101407` is the check func.

![](attachment/968c88d622d54b580bee43538bdec676.png)

There is only one return line: `return local_10 == param_2` when it is done iterating through `param_1`

Regarding `local_10`, i can see that
- `local_10 = local_10 + 1` if `param_1[i] == 'A'`
- `local_10 = local_10 << 1` if `param_1[i] == 'B'`

As `param_1` is our input, i got this for constructing *the spell* if given `param_2` (or `local_1b8`):
```
for chr in f"{by:b}":
	if chr == '1': spell = spell + 'A'
	spell = spell + 'B'
```

Taking step back to `main`, i can see that `local_1b8`  takes the bytes from  `local_1b0`, which reads from `/dev/urandom`. There is `FUN_0010138d` prints the monster's stats using all the bytes of `local_1b8`, from that we have:

`local_1b8 = (hp << 0x30) | str | (agi << 8) | (vit << 0x0) | (int << 0x18) | (end << 0x20) | (dex << 0x28) `

From here, i wrote this script that did the job:
```
import re
from pwn import *

p = process("./prob")

for i in range(10):
	p.recvuntil(b']:')
	
	monster = p.recvuntil(b'Cast your spell!: ').decode()
	in4 = [int(s) for s in re.findall(r'\d+', monster)]
	print(in4)
	
	by=0
	for j in [0,6,5,4,3,2,1]:
		by = by + in4[j]
		by = by << 8
	by = by >> 8
	
	spell = ""
	for chr in f"{by:b}":
		if chr == '1': spell = spell + 'A'
		spell = spell + 'B'
	spell = spell[:-1]
	
	print(spell)
	p.sendline(spell.encode())
p.interactive()
```

## 2. [photographer](https://dreamhack.io/wargame/challenges/1998)

![](attachment/b22796a21c2a3b9ae8504d953da5c9bb.png)
Dream gave me a binary and a .enc file.

![](attachment/0f7ebaa07b455fcb6acd3a4d84d32f59.png)

At a glance, i can see that `local_228` is our byte stream from the flag.
After `FUN_001029fa` and `FUN_00102aae` it "becomes" `local_448` (i think).

![](attachment/01b7dbb9c78bd0b4fc96ccdfd8a1b54a.png)
Now, in the loops:
- `local_480` is the index
- `FUN_00102bb6` is just getting the pointer to the next byte 
- `FUN_001024c2` is shift left, `FUN_00102489` is shift right
- `*puVar7 = uVar3` updates the new value

With that in mind, i wrote the decoder, with `r` for the `rand()`:
```
if i % 3 == 2:
	dec = (current_byte + 0x18) ^ r
elif i % 3 == 0:
	dec = ((current_byte >> 4 | current_byte << 4) - r) % 256
	dec = dec >> 1 | dec << 7
else:
	r = r % 8
	dec = current_byte << r | curr_by >> (8-r)
```

Notice that we know that it uses `srand(0xbeef)` so we can replicate all the `rand()` in the binary, the full script is written as below:

```
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.srand(0xbeef)

with open("flag.bmp.enc", 'rb') as data, open("flag.bmp", 'wb') as flag:
	i = 0
	while(True):
		cur = data.read(1)
		if (not cur): break
		current_byte = int.from_bytes(cur)
		r = libc.rand() % 256
		
		if i % 3 == 2:
			dec = (current_byte + 0x18) ^ r
		elif i % 3 == 0:
			dec = ((current_byte >> 4 | current_byte << 4) - r) % 256
			dec = dec >> 1 | dec << 7
		else:
			r = r % 8
			dec = current_byte << r | curr_by >> (8-r)
		
		flag.write(bytes([dec % 256]))
		i = i + 1
```

## 3. [similar](https://dreamhack.io/wargame/challenges/1670)

![](attachment/d260d7ab7ce87808baf2e02ebf3a2e7b.png)

It seems like it gives us a list of list, each containing 3 integer ranging from -100 to 100.
And it sorts that list using  `FUN_001017c8`.

![](attachment/f5b5b648e88cd9d51939eebb732c5eeb.png)
If we get the sorted order right, we get the flag.
#### aight.

![](attachment/ebf7b71faea8e24d993681a6976ddb77.png)
This thing compares `dVar3` & `dVar4`, let's check `FUN_001016a3`

![](attachment/5746ce191d688c819dbcc665cfed3b83.png)
We know that the `param_1`, which this function gets, is the pointer to a "list of 3 integer" in the list, so `(int)param_1` is `param_1[0]`. 
However, there is this `param_1 >> 0x20` looks a little confusing. :D

I take a look at the assembly:
![](attachment/12697c415dc881304beb8a9142050612.png)

`RBP + local_48` is `*param_1`, so  `[RBP + local_48] = param_1[0]`, `(int)` is 4 bytes so `[RBP + local_48 + 0x4] = param_1[1]` 

*ok now but why there is already a `param_1[1]` up [there](#aight)?*  ima check the assembly again
![](attachment/019fafd80f6be07aee43e652564bf1a6.png)
 This explains that the `param_1[1]` mentioned above was actually `param_1[2]` :v

Now we know how it sorts, implement it in python and we're done:
```
from math import sqrt
from pwn import *
from functools import cmp_to_key

def cal(a): 
	return (1- (a[1] + a[2] + a[0])/ (sqrt(3) * sqrt(a[1]*a[1] + a[0]*a[0] + a[2]*a[2])))

def compar(a,b):
	x = cal(a)
	y = cal(b)
	if x<y: return -1
	elif x>y: return 1
	else: return 0

r = remote('host8.dreamhack.games', 15703)
data = r.recvuntil(b'Result?').decode()
arr = [list(map(int, line.split(':')[1].split())) + [int(line.split(':')[0])] for line in data.splitlines() if ':' in line and line.split(':')[0].strip().isdigit()]
sor = sorted(arr, key=cmp_to_key(compar))
payload = " ".join(str(a[3]) for a in sor)
r.sendline(payload.encode())
r.interactive()
```

## 4. [CrabME](https://dreamhack.io/wargame/challenges/2147)

>"Con cu tám cẳng hai càng
>Một mai hai mắt rõ ràng con cua"


I think it's all here
![](attachment/d34f9284f5b9ec1c862ca8f919871a42.png)

I spotted `flagchecker()`, `lVar5` is the index, when `lVar5 == 64` the check starts

But what is that thing with `uVar6` below? 
After some time looking it up, it's checking for 1/2/3/4-byte character & building them up. 

The encoded flag is scattered at `puVar5 -> DAT_0019000 `
![](attachment/6e462053d61e5ab763195f8d98bd2dc4.png)

![](attachment/1330d73777a5f0883107c46472490293.png)
i'll rewrite this mess with x := uVar1
```
(((x >> 2 & 0b00100000 |  x >> 4 & 0b00000100 | (x << 3 & 0b10000000 |
   x >> 2 & 0b00000010 | (x >> 1 & 0b00000001 |  x << 3 & 0b00001000)
+ (x << 2 & 0b00010000) + (x << 1 & 0b01000000)) ^ 99) + 0x22 & 0xff
```
so it shuffles the bits of `x` and do several things:
```
x = 0b12345678 
 -> 0b43168257
 ```

reverse it and now we're done
right??
```

enc = bytearray(b'\xae\x00\x00\x00\x6d\x00\x00\x00\x9b\x00\x00\x00\x92\x00\x00\x00\x13\x00\x00\x00\x2b\x00\x00\x00\xc6\x00\x00\x00\xc9\x00\x00\x00\xe5\x00\x00\x00\xfa\x00\x00\x00\x96\x00\x00\x00\x0b\x00\x00\x00\x64\x00\x00\x00\x31\x00\x00\x00\xb8\x00\x00\x00\x08\x00\x00\x00\xc8\x00\x00\x00\x48\x00\x00\x00\xd2\x00\x00\x00\x30\x00\x00\x00\x60\x00\x00\x00\x04\x00\x00\x00\xfa\x00\x00\x00\x7b\x00\x00\x00\x88\x00\x00\x00\xb0\x00\x00\x00\x2f\x00\x00\x00\x7c\x00\x00\x00\xb3\x00\x00\x00\xb3\x00\x00\x00\x58\x00\x00\x00\x61\x00\x00\x00')

def shufflelelele(b):
	crab_map = [1, 3, 6 , 0, 2, 7, 5, 4]
	return sum((((((b - 0x22) & 0xff) ^ 99) >> i) & 1) << crab_map[i] for i in range(8))

print(''.join(chr(shufflelelele(b)) for b in enc[::4]))
```
...
nah
![](attachment/2a44b91770c1deea0a21f8b67a16e0d7.png)

Notice that in the `main`, our flag is 64 chr long, but there is only 32 given bytes.
A ha:![](attachment/37f633eb6e36af59888e75a19f4108dc.png)

okay now it works
```
print(''.join(f"{shufflelelele(b):02x}" for b in enc[::4]))
```


