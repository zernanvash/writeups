# SMALL RSA
``` python
from Crypto.Util.number import getPrime 
flag="FLAG*****************************" 
c="" p=getPrime(12) 
q=getPrime(12) 
N=p*q E=65537 
for l in flag: 
  c+=format(pow(ord(l),E,N), '08X') print(c)
```
**Challenge breakdown**

**Solution Script**
```python
import math
from Crypto.Util.number import inverse

def generate_primes(limit):
    """Generate a list of all prime numbers up to 'limit' using the Sieve of Eratosthenes."""
    sieve = [True] * (limit + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(math.sqrt(limit)) + 1):
        if sieve[i]:
            for j in range(i*i, limit+1, i):
                sieve[j] = False
    return [i for i, is_prime in enumerate(sieve) if is_prime]

def find_private_key(p, q, e=65537):
    """Compute the private RSA key 'd' from p, q, and e."""
    lcm = math.lcm(p-1, q-1)
    return inverse(e, lcm)
def try_decrypt(hex_string, e=65537):
    """Try to find the correct RSA key and decrypt the string."""
    chunks = [hex_string[i:i+8] for i in range(0, len(hex_string), 8)]
    ciphertext = [int(chunk, 16) for chunk in chunks]
    
    max_enc = max(ciphertext)
    primes = generate_primes(4096)

    print("Trying prime pairs to find modulus N...")

    for i in range(len(primes)):
        for j in range(i, len(primes)):
            p, q = primes[i], primes[j]
            n = p * q
            if n <= max_enc:
                continue

            try:
                d = find_private_key(p, q, e)
            except ValueError:
                continue

            # Try decrypting a few characters
            valid = True
            trial = ''
            for c in ciphertext[:3]:
                dec = pow(c, d, n)
                if dec < 32 or dec > 126:
                    valid = False
                    break
                trial += chr(dec)

            if valid:
                print(f"[+] Found plausible N = {n} (p = {p}, q = {q})")
                print(f"[+] Sample Decryption: {trial}")

                plaintext = ''
                for c in ciphertext:
                    dec = pow(c, d, n)
                    if dec < 32 or dec > 126:
                        print(f"[!] Non-printable or invalid character found: {dec}")
                        return None
                    plaintext += chr(dec)

                return plaintext

    print("[-] No valid modulus found.")
    return None


cipher_hex = "0015A15A001D7AEA000F663A001A1CFB00127B2D000353B800135A9B001D7AEA00212E6E0015A15A00064786001D57D6001D7AEA00150F64001A1CFB001D7AEA001D57D60018005E0013EDF20010858D0015A15A000823E20011654D001D57D6001D7AEA00135A9B002137060011654D0021370600150F640015A15A000353B8001D7AEA00213706000823E200064786001A1CFB00127B2D0017CEF80015A15A00150F6400213706001A1CFB000823E2"

plaintext = try_decrypt(cipher_hex)
if plaintext:
    print(f"[✓] Decrypted Flag: {plaintext}")
else:
    print("Decryption failed.")
```

