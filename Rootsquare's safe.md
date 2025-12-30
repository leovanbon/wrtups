## [Rootsquare's safe](https://dreamhack.io/wargame/challenges/1988)

performs 2 checks

![](attachment/6be153706b145ae7465225cabf76a2e4.png)

What is `(*local_178[local_180])(local_58,sVar2 & 0xffffffff)`?

![](attachment/ab792c1da69e9e7ee68f03727f6d3681.png)

`local_178` is the pointer to the *lock functions*, so this safe has 4 locks.

### The keyboard

![](attachment/50164faa9ddeb35326fdd7bcc5bcfe02.png)![](attachment/c7a040d702e48ab6d3dbb96f1d1f3b93.png)

```
lines = [re.findall(r'\| (.*) \|', input()) for i in range(4)]
keys = [key for l in lines for li in l for key in li.split()]
```

### The 1st lock

![](attachment/b5239c8c79f0bf65bf1d959c6daa1f01.png)
```
print("".join(c for i in range(8) for c in chrs if (ord(c) % 32) % 4 == 0 and (ord(c) % 32) // 4 == i))
```


### The 2nd lock

![](attachment/3ed7e28fb83c11202bb24d70a042d182.png)

```
print("".join(c for i in [(year>>10) & 0x1f, (year>>5) & 0x1f, year & 0x1f, month, day] for c in chrs if ord(c) % 32 == i))
```

### The 3rd lock

![](attachment/65fe80bde71eca49e9fc4dcda7d94661.png)

oh i forgor this 

![](attachment/4dc2342ca28672369ded5b69a7b0c8b5.png)

```
key = []
for j in range(1,33):
	s = j*j
	if str(s) == str(s)[::-1] and s >= 10: key.extend([(s//32) % 32, s % 32])
	if len(key) >= 6: break

print("".join(c for i in key for c in chrs if ord(c) % 32 == i))
```

### The last lock

![](attachment/4d9dad3e6e64a1bf1546176e80a959cb.png)

pardon me 
```
print("".join(c for i in (lambda x: [int(x[i:i+5], 2) for i in range(0, len(x), 5)])("".join(f"{ord(c):08b}" for c in "Rootsquare")) for c in chrs if ord(c) % 32 == i))
```

### Flag

[full script](https://github.com/leovanbon/mypyparsescripts/blob/main/savesafesafe.py)

poc:

![](attachment/89862e5f7f6baca602788b63326fa065.png)

`DH{$eeing_Dollar_$ign$_$afe_Cracker!}`

