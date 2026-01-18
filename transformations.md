[[rev probs]]

## get input

![](attachment/aacb179ffee5f956e303b5f5c1c12123.png)
input is 32 bytes
each byte is chopped into bits, each bit get padded with 0s to get a byte
so it turned into an array of 256 bytes
## operations
![](attachment/5a7f1a562e4d0ef6952a4b02f60fec8c.png)

`action = "123423123413122123432132121243123123431232123142131342121324123241234"`

### `sub_1A80` (case 4)

![](attachment/6b175b1144cd8a8ac67a88ea4d858f48.png)
#### a1
![](attachment/9bec72c8687da7a5094e3b5cd9c6c680.png)

just xoring

### `sub_198C` (case 3)

![](attachment/4d40d4392ba9376629c004198a5155e8.png)
quick math:
`a1[16*a + b] = a1[16*? + ?]`
let: `15 - j = a`
then: `j = 15 - a`  and `i = b`

so reverse is
```
temp = [0] * 256
for a in range(16):
	for b in range(16):
		temp[16*a + b] = a1[16*b + (15-a)]
a1 = temp
```

### `sub_1898` (case 2)
![](attachment/dcb2058e4da392dab24f9931afd5c648.png)
similar here

```
for a in range(16):
	for b in range(16):
		temp[16*a + b] = a1[16*(15-a) + b]
```

### `sub_17A5` (case 1)

![](attachment/2485b4e449e9d70fba5a3883ce4eb5d8.png)

```
for a in range(16):
	for b in range(16):
		temp[16*a + b] = a1[16*a + (15-b)]
```

## last part

![](attachment/77f03b0dcce1924afcbda2f09c631592.png)
just put things back together

## PoC

`DH{Flip_Spin_Switch_to_the_goal}`
script: https://github.com/leovanbon/mypyparsescripts/blob/main/trsnfmatns.py