# 🔐 RC5 Cipher Implementation

This repository contains an implementation of the **RC5 cipher**, a symmetric-key block cipher designed by Ronald Rivest in 1994. RC5 is known for its simplicity, speed, and flexibility due to its parameterized design. This implementation demonstrates how RC5 performs encryption and decryption using a customizable key, word size, and number of rounds.

---

## 📌 Overview

RC5 is a symmetric-key block cipher that transforms plaintext into ciphertext using a secret key. Unlike fixed-design ciphers, RC5 is highly customizable, allowing users to define:

- `w`: Word size (16, 32, or 64 bits)
- `r`: Number of rounds (recommended ≥12)
- `b`: Key length in bytes (up to 255)

RC5 encrypts data blocks of `2 × w` bits using simple and fast operations: XOR, modular addition, and data-dependent circular shifts.

---

## 🔐 Key Features

- **Symmetric Cipher** – Same key used for both encryption and decryption  
- **Block Cipher** – Encrypts fixed-size blocks (2 words = 2 × w bits)  
- **Highly Parameterized** – Adjustable word size, rounds, and key length  
- **Lightweight Operations** – Uses XOR, addition, and bitwise rotations  
- **Data-Dependent Rotations** – Increases cryptographic complexity  
- **Flexible and Efficient** – Suitable for hardware and software implementations  

---

## 🧠 Terminology

| Term                | Meaning                                                                 |
|---------------------|-------------------------------------------------------------------------|
| **Word (`w`)**       | Basic unit of data (e.g., 32 bits)                                     |
| **Block**            | Two words = 2 × w bits (e.g., 64-bit block if w = 32)                  |
| **Key (`K`)**        | Secret key provided by user                                            |
| **Key Length (`b`)** | Length of key in bytes (0–255 bytes)                                   |
| **Rounds (`r`)**     | Number of times the encryption function is applied                     |
| **Subkeys (`S`)**    | Array of 2(r+1) derived keys used in encryption/decryption             |
| **Magic Constants**  | `P` and `Q` constants for subkey generation using `e` and `φ`          |
| **⊕ (XOR)**          | Bitwise exclusive OR operation                                         |
| **+ (mod 2^w)**      | Addition modulo 2^w                                                    |
| **<<< / >>>**        | Circular left/right rotation                                           |

---

## 🔄 How RC5 Works

RC5 involves three main stages: **Key Expansion**, **Encryption**, and **Decryption**. Here's how each stage works in detail:

---

### 🔧 1. Key Expansion

RC5 requires a subkey array `S[0 ... 2r+1]`. This is generated from the user-provided key using two "magic constants":

- `P = Odd((e − 2) × 2^w)` where e ≈ 2.71828
- `Q = Odd((φ − 1) × 2^w)` where φ ≈ 1.61803

#### Steps:

1. **Initialize subkeys**:

   ```plaintext
   S[0] = P
   For i = 1 to 2r + 1:
       S[i] = S[i-1] + Q```

2. **Convert key (K) into array L[] of c = ceil(b / u) words, where u = w / 8**

3. **Mix S[] and L[] together for 3 × max(c, 2r + 2) iterations:**

    ```plaintext
    A = B = 0
    For i = 0 to 3 × max(c, 2r+2) - 1:
        A = S[i % t] = (S[i % t] + A + B) <<< 3
        B = L[i % c] = (L[i % c] + A + B) <<< (A + B)```

4. **This results in a securely randomized subkey array S[].**


### 🔒 2. Encryption

Given plaintext block split into two w-bit words A and B, and the subkeys S[], encryption is performed as:

1. **Initial Key Mixing:**

```plaintext
A = A + S[0]
B = B + S[1]
```

2.  **r Rounds of Transformation:**
```plaintext
For i = 1 to r:
    A = ((A ⊕ B) <<< B) + S[2i]
    B = ((B ⊕ A) <<< A) + S[2i + 1]
```

3. **After the final round, A and B together form the ciphertext block.**


### 🔓 3. Decryption

To decrypt, apply the inverse of the encryption steps:

1. **r Rounds in Reverse Order:**
```plaintext
For i = r down to 1:
    B = ((B - S[2i + 1]) >>> A) ⊕ A
    A = ((A - S[2i]) >>> B) ⊕ B
```

2. **Final Key Unmixing:**
```plaintext 
B = B - S[1]
A = A - S[0]
```

3. **The result is the original plaintext A, B.**