# jwt-secret-finder
Multi-threaded JWT brute-force decryptor in Rust. Inspired by https://github.com/brendan-rius/c-jwt-cracker.
  
## Running

```
git clone https://github.com/llambda/jwt-secret-finder.git
cd jwt-secret-finder
cargo run --release
```

## Example

```
./target/release/jwtc -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE 
Opt { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE", alphabet: "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789", max_length: 6 }
["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", "cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE"]

Presented Header: {"alg":"HS256","typ":"JWT"}
Presented Payload: {"sub":"1234567890","name":"John Doe","admin":true}
Presented Signature (len) 32: p�'��������n�G�N�gj��T��}W21

Checking secrets of length 1
Checking secrets of length 2
Checking secrets of length 3
Checking secrets of length 4
Found! Created signature    : p�'��������n�G�N�gj��T��}W21 using the secret: Sn1f
```

Takes about 34 seconds on my machine to find the secret "Sn1f".
