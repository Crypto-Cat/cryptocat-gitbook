---
name: Malayo (2025)
event: PwnSec CTF 2025
category: Rev
description: Writeup for Malayo (Rev) - PwnSec CTF (2025) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Malayo

## Description

> Under the sound of the wild, The Malayopython appears

## Solution

The file is compiled python code.

```bash
file Malayo.pyc

Malayo.pyc: Byte-compiled Python module for CPython 3.12 or newer, timestamp-based, .py timestamp: Sat Nov  1 02:31:58 2025 UTC, .py size: 10094 bytes
```

### Decompiling Python Bytecode

I have reversed these by hand in the past, but hopefully we can decompile this one. I used `--break-system-packages` because I'm too lazy/chaotic for virtual envs.

```bash
pip install decompyle3 --break
```

Moment of truth..

```bash
decompyle3 Malayo.pyc > Malayo_decompiled.py

# Unsupported bytecode in file Malayo.pyc
# Unsupported Python version, 3.13.0, for decompilation
```

As I feared, it is not supported. ChatGPT gave me a script.

```python
import marshal, dis, types

def walk(code, prefix=""):
    print(prefix + "code object:", code.co_name)
    print(prefix + "  args:", code.co_varnames[:code.co_argcount])
    print(prefix + "  names:", code.co_names)
    print(prefix + "  consts:", code.co_consts)
    print()
    dis.dis(code)
    print("\n" + "-"*60 + "\n")
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            walk(c, prefix + "  ")

with open("Malayo.pyc","rb") as f:
    f.read(16)
    root = marshal.load(f)

walk(root)
```

It printed a lot of python assembly, function names, strings etc but crashed out due to recursion. Here's a snippet:

```bash
python plz.py

code object: <module>
  args: ()
  names: ('z3', 'random', 'hashlib', 'base64', 'string', 'time', 'sys', 'itertools', 'permutations', 'combinations', 'functools', 'reduce', 'collections', 'defaultdict', 'Crypto.Cipher', 'AES', 'Crypto.Util.Padding', 'pad', 'unpad', 'os', 'STRINGS', 'list', 'range', 'NUMBERS', 'str', 'Xx', 'chr', 'xX', 'XX', 'md5', 'encode', 'hexdigest', 'XXx', 'randint', 'RND1', 'hash_function_1', 'hash_function_2', 'string_manipulator', 'operations', 'CONSTRAINTSS', 'CALCSS', 'TUPLES', 'set', 'SETS', 'Class1', 'Class2', 'obj_1', 'obj_2', 'Uu', 'uU', 'UU', 'UUu', 'you', 'intenTIONAL_FUNCS', 'MEGA_DUMMY_DATA', 'Dd', '__name__', 'dummy_additional', 'dummy_final', 'print', 'input', 'user_input')
  consts: (0, None, ('permutations', 'combinations'), ('reduce',), ('defaultdict',), ('AES',), ('pad', 'unpad'), 'Lorem ipsum dolor sit amet consectetur adipiscing elit', 100, 'The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog
<SNIP>
01234567890123456789', '!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?!@#$%^&*()_+-=[]{}|;:,.<>?', 20, 10000, 1000, 2, 500, 3, 30, 5000, 26, 65, 2000, 'key_', 'value_', 10, 50, <code object hash_function_1 at 0x7ff7389d84b0, file "./OPz.py", line 42>, <code object hash_function_2 at 0x7ff738bc8d50, file "./OPz.py", line 53>, <code object string_manipulator at 0x7ff738b19e30, file "./OPz.py", line 57>, <code object operations at 0x7ff738be8c90, file "./OPz.py", line 66>, <code object CONSTRAINTSS at 0x2da4f440, file "./OPz.py", line 75>, <code object CALCSS at 0x2da55200, file "./OPz.py", line 90>, 4, <code object Class1 at 0x7ff7389fe5b0, file "./OPz.py", line 127>, 'Class1', <code object Class2 at 0x7ff738a0da70, file "./OPz.py", line 142>, 'Class2', <code object Uu at 0x7ff738bc97d0, file "./OPz.py", line 156>, <code object uU at 0x2da12e30, file "./OPz.py", line 166>, <code object UU at 0x2d9f9d40, file "./OPz.py", line 201>, <code object UUu at 0x2da294b0, file "./OPz.py", line 232>, <code object you at 0x7ff738b1a010, file "./OPz.py", line 254>, <code object intenTIONAL_FUNCS at 0x7ff738b7bbb0, file "./OPz.py", line 269>, 5, ('strings', 'numbers', 'dicts', 'lists', 'tuples', 'sets'), <code object Dd at 0x2da54df0, file "./OPz.py", line 318>, '__main__', 'Ready for input.', 'Enter the flag: ', "\nCongratulations! That's the correct flag!", 'Flag: ', 'Verification hash: ', 'Cryptographic validation passed!', '\nIncorrect flag. Please try again.', (100,))
```

### Testing Functionality

Let's try and run it.

```bash
python Malayo.pyc

RuntimeError: Bad magic number in .pyc file
```

Fantastic! I downloaded and installed `python3.13`

```bash
python3.13 --version

Python 3.13.0a5
```

Then create a virtual environment.

```bash
python3.13 -m venv v313

source v313/bin/activate
```

Unfortunately, it still says "bad magic number". We can run the following file in the venv:

```python
import marshal, types
with open("Malayo.pyc","rb") as f:
    f.read(16)
    code = marshal.load(f)
exec(code)
```

Install missing dependencies.

```bash
pip install z3-solver pycryptodome
```

Now the program runs!

```bash
python run_pyc.py

Ready for input.
Enter the flag: meow

Incorrect flag. Please try again.
```

### Dumping Constants

Not much use, but ChatGPT gives me something I can work with.

```python
import marshal
import types
import dis

with open("Malayo.pyc", "rb") as f:
    f.read(16)
    root = marshal.load(f)

def walk(code, depth=0):
    indent = "  " * depth
    print(indent + "code:", code.co_name)
    print(indent + "consts:",
          [c for c in code.co_consts if isinstance(c, str)])
    print()
    dis.dis(code)
    print("\n" + indent + "-"*40 + "\n")
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            walk(c, depth + 1)

walk(root)
```

That dumps all the constants and a python assembly, but there's nearly 6000 lines to work through 😬

ChatGPT suggests we should focus on some specific targets relevant to the z3 solver import.

```python
import marshal
import types
import dis

with open("Malayo.pyc", "rb") as f:
    f.read(16)
    code = marshal.load(f)

mod = types.ModuleType("malayo")
exec(code, mod.__dict__)

targets = [
    "you",
    "UUu",
    "UU",
    "uU",
    "Uu",
    "CONSTRAINTSS",
    "CALCSS"
]

for name in targets:
    func = getattr(mod, name, None)
    if func is None or not callable(func):
        continue
    c = func.__code__
    print("=== function", name, "===")
    print("args:", c.co_varnames[:c.co_argcount])
    print("names:", c.co_names)
    print("consts:", c.co_consts)
    print()
    dis.dis(c)
    print("\n" + "="*60 + "\n")
```

## Reversing the Assembly

We get ~1.2k lines of output this time, and six mentions of the word "flag".

### you()

The `you` function calls the "names" functions in order.

-   `257` checks the length of the flag is is 36 characters (`user_flag`)
-   `259` converts each char to an integer (`f`)
-   `f` gets passed through the `'Uu', 'uU', 'UU', 'UUu'` functions (in order)

```python
=== function you ===
args: ('user_flag',)
names: ('CALCSS', 'hash_function_1', 'len', 'ord', 'Uu', 'uU', 'UU', 'UUu')
consts: (None, 36, False, True)

 254            RESUME                   0

 255            LOAD_GLOBAL              1 (CALCSS + NULL)
                CALL                     0
                STORE_FAST               1 (dummy_result)

 256            LOAD_GLOBAL              3 (hash_function_1 + NULL)
                LOAD_FAST                1 (dummy_result)
                CALL                     1
                STORE_FAST               2 (_)

 257            LOAD_GLOBAL              5 (len + NULL)
                LOAD_FAST                0 (user_flag)
                CALL                     1
                LOAD_CONST               1 (36)
                COMPARE_OP             119 (bool(!=))
                POP_JUMP_IF_FALSE        1 (to L1)

 258            RETURN_CONST             2 (False)

 259    L1:     LOAD_FAST                0 (user_flag)
                GET_ITER
                LOAD_FAST_AND_CLEAR      3 (c)
                SWAP                     2
        L2:     BUILD_LIST               0
                SWAP                     2
                GET_ITER
        L3:     FOR_ITER                14 (to L4)
                STORE_FAST               3 (c)
                LOAD_GLOBAL              7 (ord + NULL)
                LOAD_FAST                3 (c)
                CALL                     1
                LIST_APPEND              2
                JUMP_BACKWARD           16 (to L3)
        L4:     END_FOR
                POP_TOP
        L5:     STORE_FAST               4 (f)
                STORE_FAST               3 (c)

 260            NOP

 261    L6:     LOAD_GLOBAL              9 (Uu + NULL)
                LOAD_FAST                4 (f)
                CALL                     1
                TO_BOOL
                POP_JUMP_IF_TRUE         1 (to L8)
        L7:     RETURN_CONST             2 (False)

 262    L8:     LOAD_GLOBAL             11 (uU + NULL)
                LOAD_FAST                4 (f)
                CALL                     1
                TO_BOOL
                POP_JUMP_IF_TRUE         1 (to L10)
        L9:     RETURN_CONST             2 (False)

 263   L10:     LOAD_GLOBAL             13 (UU + NULL)
                LOAD_FAST                4 (f)
                CALL                     1
                TO_BOOL
                POP_JUMP_IF_TRUE         1 (to L12)
       L11:     RETURN_CONST             2 (False)

 264   L12:     LOAD_GLOBAL             15 (UUu + NULL)
                LOAD_FAST                4 (f)
                CALL                     1
                TO_BOOL
                POP_JUMP_IF_TRUE         1 (to L14)
       L13:     RETURN_CONST             2 (False)

 265   L14:     RETURN_CONST             3 (True)

  --   L15:     SWAP                     2
                POP_TOP

 259            SWAP                     2
                STORE_FAST               3 (c)
                RERAISE                  0

  --   L16:     PUSH_EXC_INFO

 266            POP_TOP

 267   L17:     POP_EXCEPT
                RETURN_CONST             2 (False)

  --   L18:     COPY                     3
                POP_EXCEPT
                RERAISE                  1
ExceptionTable:
  L2 to L5 -> L15 [2]
  L6 to L7 -> L16 [0]
  L8 to L9 -> L16 [0]
  L10 to L11 -> L16 [0]
  L12 to L13 -> L16 [0]
  L16 to L17 -> L18 [1] lasti
```

Taking a look at the `Uu` function, we can actually just [convert the constants from decimal](<https://gchq.github.io/CyberChef/#recipe=From_Decimal('Comma',false)&input=MTAyLCAxMDgsIDk3LCAxMDMsIDEyMywgODUsIDk1>), e.g. `102, 108, 97, 103, 123, 85, 95` becomes `flag{U_` ✅

```python
=== function Uu ===
args: ('f',)
names: ()
consts: (None, 0, 102, False, 1, 108, 2, 97, 3, 103, 4, 123, 5, 85, 6, 95, True)

156           RESUME                   0

157           LOAD_FAST                0 (f)
              LOAD_CONST               1 (0)
              BINARY_SUBSCR
              LOAD_CONST               2 (102)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L1)
              RETURN_CONST             3 (False)

158   L1:     LOAD_FAST                0 (f)
              LOAD_CONST               4 (1)
              BINARY_SUBSCR
              LOAD_CONST               5 (108)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L2)
              RETURN_CONST             3 (False)

159   L2:     LOAD_FAST                0 (f)
              LOAD_CONST               6 (2)
              BINARY_SUBSCR
              LOAD_CONST               7 (97)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L3)
              RETURN_CONST             3 (False)

160   L3:     LOAD_FAST                0 (f)
              LOAD_CONST               8 (3)
              BINARY_SUBSCR
              LOAD_CONST               9 (103)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L4)
              RETURN_CONST             3 (False)

161   L4:     LOAD_FAST                0 (f)
              LOAD_CONST              10 (4)
              BINARY_SUBSCR
              LOAD_CONST              11 (123)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L5)
              RETURN_CONST             3 (False)

162   L5:     LOAD_FAST                0 (f)
              LOAD_CONST              12 (5)
              BINARY_SUBSCR
              LOAD_CONST              13 (85)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L6)
              RETURN_CONST             3 (False)

163   L6:     LOAD_FAST                0 (f)
              LOAD_CONST              14 (6)
              BINARY_SUBSCR
              LOAD_CONST              15 (95)
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_TRUE         1 (to L7)
              RETURN_CONST             3 (False)

164   L7:     RETURN_CONST            16 (True)
```

There's too much code in the the rest of the functions to paste here and go through line by line, so here's a quick summary:

-   `uU(f)` adds a lot of arithmetic and "sum of squares" constraints that fix most of the middle of the flag and force a various indices to be equal.
-   `UU(f)` adds more linear constraints and one relation that links positions 27 and 30.
-   `UUu(f)` does the crypto: it derives an AES key from the flag, encrypts part of it, compares against a stored ciphertext, checks `sum(f) == 3217`, and enforces that the last character is `}`.

We can ask ChatGPT to make a z3 solver that satisfies all the constraints.

```python
from z3 import IntVector, Solver, Or, Sum, sat

# 36 bytes of the flag
f = IntVector("f", 36)

s = Solver()

# printable-ish ASCII
for i in range(36):
    s.add(f[i] >= 32, f[i] <= 126)

# Uu: "flag{U_"
fixed_prefix = [102, 108, 97, 103, 123, 85, 95]
for i, v in enumerate(fixed_prefix):
    s.add(f[i] == v)

# uU / UU constraints
s.add(f[7] == 75)   # 'K'
s.add(f[8] == 51)   # '3'
s.add(f[9] == 51)   # '3'
s.add(f[10] == 112)  # 'p'
s.add(f[11] == 95)   # '_'
s.add(f[12] == 49)   # '1'
s.add(f[13] == 116)  # 't'
s.add(f[14] == 95)   # '_'
s.add(f[15] == 116)  # 't'
s.add(f[16] == 104)  # 'h'
s.add(f[17] == 52)   # '4'
s.add(f[18] == 116)  # 't'
s.add(f[19] == 95)   # '_'
s.add(f[20] == 119)  # 'w'
s.add(f[21] == 52)   # '4'
s.add(f[22] == 121)  # 'y'
s.add(f[23] == 95)   # '_'
s.add(f[24] == 48)   # '0'
s.add(f[25] == 114)  # 'r'
s.add(f[26] == 95)   # '_'
s.add(f[28] == 51)   # '3'
s.add(f[29] == 52)   # '4'
s.add(f[31] == 51)   # '3'
s.add(f[32] == 95)   # '_'
s.add(f[33] == 49)   # '1'
s.add(f[34] == 116)  # 't'
s.add(f[35] == 125)  # '}'

# Sum-of-squares constraints from uU condensed to equalities:
s.add(f[9] == f[8])
s.add(f[28] == f[8])
s.add(f[31] == f[8])
s.add(f[14] == f[11])
s.add(f[19] == f[11])
s.add(f[23] == f[11])
s.add(f[26] == f[11])
s.add(f[32] == f[11])
s.add(f[15] == f[13])
s.add(f[18] == f[13])
s.add(f[34] == f[13])
s.add(f[21] == f[17])
s.add(f[29] == f[17])
s.add(f[33] == f[12])

# UU last constraint: (f[27]-76)*(f[30]-118) == 0
# and UUu sum constraint: sum(f) == 3217
s.add(Sum(f) == 3217)
s.add(Or(f[27] == 76, f[30] == 118))

if s.check() != sat:
    raise SystemExit("no solution found")

m = s.model()
bytes_flag = [m[f[i]].as_long() for i in range(36)]
flag = "".join(chr(x) for x in bytes_flag)
print("z3 candidate:", flag)
```

If we run the script, we'll get the correct flag.

```bash
python z3_solve.py

z3 candidate: flag{U_K33p_1t_th4t_w4y_0r_L34v3_1t}
```

Alternatively, we can just paste the whole disassembled output into ChatGPT; it will give the flag directly 🙃

```python
import marshal, types

with open("Malayo.pyc","rb") as f:
    f.read(16)
    code = marshal.load(f)

mod = types.ModuleType("malayo")
exec(code, mod.__dict__)

flag = "flag{U_K33p_1t_th4t_w4y_0r_L34v3_1t}"
print(mod.you(flag))
```

Flag: `flag{U_K33p_1t_th4t_w4y_0r_L34v3_1t}`
