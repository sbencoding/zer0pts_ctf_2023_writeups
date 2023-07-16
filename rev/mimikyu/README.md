# mimikyu (rev)
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we get an x86 ELF binary with 2 of its dependencies.
Loading the binary into ghidra, we see the `LoadLibraryA` function, name after the same function in windows, which opens `dll` files and return a handle to them.

Since there's one for `libc` and another one for `libgmp`, we can name the result of these functions to be the names of the library:
```c
  libc = LoadLibraryA("libc.so.6");
  if (libc == 0) {
                    /* WARNING: Subroutine does not return */
    __assert_fail("hLibc != NULL","main.c",0x4a,(char *)&__PRETTY_FUNCTION__.0);
  }
  libgmp = LoadLibraryA("libgmp.so");
  if (libgmp == 0) {
                    /* WARNING: Subroutine does not return */
    __assert_fail("hGMP != NULL","main.c",0x4c,(char *)&__PRETTY_FUNCTION__.0);
  }
```

Now we see code like:
```c
  ResolveModuleFunction(libgmp,0x71b5428d,local_48);
  ResolveModuleFunction(libgmp,0x71b5428d,local_38);
  ResolveModuleFunction(libgmp,0x71b5428d,local_28);
  ResolveModuleFunction(libc,0xfc7e7318,_main);
  ResolveModuleFunction(libc,0x9419a860,stdout,0);
```

This is going to get a function from the specified library, based on the specified hash, and call that function with the given arguments (with which the decompiler struggles a bit).

This is taken from the windows world again, where malware commonly obfuscates library calls as such (finding a function inside some library by looking for hashes).
In my experience the best way to deal with this is to execute the binary and see what the result of the function resolver is (given that we are allowed to execute the binary).
Then I add the actual functions (and sometimes the arguments passed to them) as comments above the resolve function.

For example the above block becomes:
```c
                    /* __gmpz_init */
  ResolveModuleFunction(libgmp,0x71b5428d,local_48);
                    /* __gmpz_init */
  ResolveModuleFunction(libgmp,0x71b5428d,local_38);
                    /* __gmpz_init */
  ResolveModuleFunction(libgmp,0x71b5428d,local_28);
                    /* srandom(0xfa1e0ff3) */
  ResolveModuleFunction(libc,0xfc7e7318,_main);
                    /* setbuf */
  ResolveModuleFunction(libc,0x9419a860,stdout,0);
```

After this initial setup all of our characters are checked to be in the printable ASCII range:
```c
  printf("Checking...");
  for (local_80 = 0; local_80 < 0x28; local_80 = local_80 + 1) {
                    /* isprint */
    iVar1 = ResolveModuleFunction(libc,0x4e8a031a,(int)user_input[local_80]);
    if (iVar1 == 0) goto LAB_00101ce7;
  }
```

Then begins the checking procedure of the input:
```c
  for (local_78 = 0; local_78 < 0x28; local_78 = local_78 + 4) {
                    /* __gmpz_set_ui */
    ResolveModuleFunction(libgmp,0xf122f362,local_38,1);
    for (local_70 = 0; local_70 < 3; local_70 = local_70 + 1) {
                    /* putchar */
      ResolveModuleFunction(libc,0xd588a9,0x2e);
                    /* rand */
      iVar1 = ResolveModuleFunction(libc,0x7b6cea5d);
      cap(libc,libgmp,(long)(iVar1 % 0x10000),local_48);
                    /* gpmz_mul */
      ResolveModuleFunction(libgmp,0x347d865b,local_38,local_38,local_48);
    }
                    /* putchar */
    ResolveModuleFunction(libc,0xd588a9,0x2e);
                    /* rand */
    iVar1 = ResolveModuleFunction(libc,0x7b6cea5d);
    cap(libc,libgmp,(long)(iVar1 % 0x10000),local_28);
                    /* gmpz_set_ui */
    ResolveModuleFunction(libgmp,0xf122f362,local_48,*(undefined4 *)(user_input + local_78));
                    /* gmpz_powm */
    ResolveModuleFunction(libgmp,0x9023667e,local_48,local_48,local_28,local_38);
                    /* gmpz_cmp_ui */
    iVar1 = ResolveModuleFunction
                      (libgmp,0xb1f820dc,local_48,*(undefined8 *)(encoded + (local_78 >> 2) * 8));
    if (iVar1 != 0) goto LAB_00101ce7;
  }
  puts("\nCorrect!");
```

I have analyzed this section a bit dynamically, but didn't spend the time to fully understand the calculations being done here.

In short: the password is checked in 4 byte chunks. For each chunk we compute 2 values, that are independent of the user input, with the `cap` function. We combine these values with the user input, resulting in an 8-byte value, which will be checked against the `encoded` array (hardcoded 8-byte values for each 4-byte user input block). As soon as a check fails for a given block, the binary exits.

Because of this we can guess the flag 4-bytes at a time, which is not that bad to bruteforce, especially given the constraint to the ASCII printable range. Therefore I only needed to understand how the 2 generated values are combined with the user input, as it turns out it is pretty simple: `check = user^G1 % G2`.

Now all that was left to do is to get all `G1, G2` pairs, which again do not depend on the user input, so we can just fix the result of `mpz_cmp_ui` and inspect the arguments to all calls of `mpz_powm`.

The library functions are called at `ResolveModulefunction+0x311`, so I set a breakpoint here with GDB.
Now to fake the `mpz_cmp_ui` result, we can just go `n`, then `set $rax=0` and continue, to make it seem that the current user input part is correct.

To inspect arguments to the `mpz_powm` function, the following can be done:
1. Hit the breakpoint on the `call` instruction to the `mpz_powm` function
2. `x/xg *(long*)($rdx+8)` to get the exponent
3. `x/xg *(long*)($rcx+8)` to get the modulus

[This documentation](https://machinecognitis.github.io/Math.Gmp.Native/html/0fa7cbf3-e8f4-6b14-d829-8aa663e77c74.htm) can be used to understand what `libgmp` functions do, and what their arguments are.

Armed with all exponent, modulus pairs, and the extracted `encoded` blob from the binary, I wrote `solve.py` which bruteforces each 4-byte block of the flag (except for the first 4-bytes `zer0`, technically the first 8 is also known, but I left the 2nd 4-bytes in there as a proof of concept that the algorithm produces correct output).
