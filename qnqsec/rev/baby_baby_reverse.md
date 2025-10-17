tools: GHIDRA

file: main (elf, not stripped)

when we run ./main, it asks for a key.


then we decompile the binary and check inside the main function,
we will see a byte array local_228 that contains a string "Th1s_1s_th3_k3y".

``` C
pcVar1 = fgets((char *)(local_228 + 0x10),0x200,stdin);
```
here we add the input to the existing byte array that well later use.

then;
``` C
    local_248 = strlen((char *)(local_228 + 0x10));
    if ((local_248 != 0) && (local_228[local_248 + 0xf] == 10)) {
      local_228[local_248 + 0xf] = 0;
      local_248 = local_248 - 1;
    }
    if (local_248 == 0x29) {
      local_24a = 0;
      for (local_240 = 0; local_240 < 0x29; local_240 = local_240 + 1) {
        local_24a = local_24a |
                    encrypted[local_240] ^ local_228[local_240 % 0xf] ^ local_228[local_240 + 0x10];
      }
```
checks if local_248 length is 41, means our input should be 41 characters.

now for the key encyption,
```C
      for (local_240 = 0; local_240 < 0x29; local_240 = local_240 + 1) {
        local_24a = local_24a |
                    encrypted[local_240] ^ local_228[local_240 % 0xf] ^ local_228[local_240 + 0x10];
      }
      if (local_24a == 0) {
        puts("Correct!");
      }
```
the loop use OR to assert if values on encrypted array(stored on .data) XORed to the given characters on local_228's first 16 bytes ("Th1s_1s_th3_k3y") then XORed again to our input, will result to zero.
if at the end of the loop, local_24a is zero then we got the correct input!

so all the info, we need to imitate the loop to a python script to get the correct input/flag.


``` python
from hex_to_array import *

# Read the encrypted bytes
raw_data = hex_to_array('main_data.txt', 1, True)
encrypted = raw_data[:41]

# Known key[0..15]
key_prefix = [ord(c) for c in "Th1s_1s_th3_k3y"]

# Reconstruct the 41-byte user input part
decrypted = []
for i in range(41):
    decrypted_byte = encrypted[i] ^ key_prefix[i % 15]
    decrypted.append(decrypted_byte)

# Convert to readable string
flag = bytes(decrypted).decode(errors='ignore')

print("Flag:", flag)
```

ps. hex_to_array is a custom script i made, you can manually input the hex bytes from the .data of the binary file
