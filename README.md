# Mini-AES Project
For Cryptography Middle Semester Project

## Deskripsi Proyek
AES (Advanced Encryption Standard) adalah algoritma kriptografi blok yang kuat namun kompleks. Untuk keperluan pembelajaran, Mini-AES dirancang sebagai versi ringkas yang tetap mempertahankan struktur inti AES seperti SubBytes, ShiftRows, MixColumns, dan AddRoundKey, namun dengan ukuran blok dan kunci yang lebih kecil. Project ini bertujuan untuk memberikan pemahaman praktis tentang bagaimana cipher modern bekerja dalam bentuk yang sederhana.

---

## Table of Contents
- [Spesifikasi Proyek](#spesifikasi-proyek)
  - [Spesifikasi Dasar (100 poin)](#1-spesifikasi-dasar-100-poin)
  - [Spesifikasi Tambahan (18-20 poin)](#2-spesifikasi-tambahan-18-20-poin)
- [Kesimpulan](#kesimpulan)

---

# Spesifikasi Proyek

## 1. Spesifikasi Dasar (100 poin)

### 1.1 Representasi Plaintext dan Key (16-bit)
```python
def _bits_to_state(self, bits):
    state = np.zeros((2, 2), dtype=np.uint8)
    state[0, 0] = (bits >> 12) & 0xF
    state[0, 1] = (bits >> 8) & 0xF
    state[1, 0] = (bits >> 4) & 0xF
    state[1, 1] = bits & 0xF
    return state
```
**Penjelasan:** Mengkonversi 16-bit integer menjadi matriks 2x2 berisi 4-bit nibbles.

### 1.2 SubNibbles (S-Box 4-bit)
```python
def sub_nibbles(self, state):
    result = np.zeros_like(state)
    for i in range(2):
        for j in range(2):
            result[i, j] = self.SBOX[int(state[i, j])]
    return result
```
**Penjelasan:** Substitusi setiap elemen matriks menggunakan tabel S-Box.

### 1.3 ShiftRows
```python
def shift_rows(self, state):
    result = state.copy()
    result[1, 0], result[1, 1] = state[1, 1], state[1, 0]
    return result
```
**Penjelasan:** Menukar posisi elemen pada baris kedua matriks.

### 1.4 MixColumns (GF(2^4))
```python
def mix_columns(self, state):
    result = np.zeros_like(state)
    for j in range(2):
        result[0, j] = self.gf_mult(1, state[0, j]) ^ self.gf_mult(4, state[1, j])
        result[1, j] = self.gf_mult(4, state[0, j]) ^ self.gf_mult(1, state[1, j])
    return result
```
**Penjelasan:** Mengalikan kolom dengan matriks tetap dalam bidang GF(2^4).

### 1.5 AddRoundKey
```python
def add_round_key(self, state, round_key):
    return np.bitwise_xor(state, round_key)
```
**Penjelasan:** Melakukan XOR antara matriks state dengan round key.

### 1.6 Jumlah Round = 3
```python
for r in range(1, 3):
    state = self.sub_nibbles(state)
    state = self.shift_rows(state)
    state = self.mix_columns(state)
    state = self.add_round_key(state, round_keys[r])

state = self.sub_nibbles(state)
state = self.shift_rows(state)
state = self.add_round_key(state, round_keys[3])
```
**Penjelasan:** Dua ronde utama + satu ronde akhir tanpa MixColumns.

### 1.7 Key Expansion
```python
def key_expansion(self, key):
    round_keys = [None] * 4
    round_keys[0] = key.copy()
    rcon = [0x1, 0x2, 0x4]
    for i in range(1, 4):
        prev_key = round_keys[i-1]
        rotated_col = np.array([prev_key[1,1], prev_key[0,1]])
        subbed_col = np.array([self.SBOX[int(rotated_col[0])], self.SBOX[int(rotated_col[1])]])
        new_key = np.zeros_like(prev_key)
        new_key[0,0] = prev_key[0,0] ^ subbed_col[0] ^ rcon[i-1]
        new_key[1,0] = prev_key[1,0] ^ subbed_col[1]
        new_key[0,1] = prev_key[0,1] ^ new_key[0,0]
        new_key[1,1] = prev_key[1,1] ^ new_key[1,0]
        round_keys[i] = new_key
    return round_keys
```
**Penjelasan:** Membuat 4 round keys dari key awal menggunakan rotasi, substitusi, dan RCON.

### 1.8 Program Input/Output dan Test Case
```python
plaintext1 = 0xABCD
key1 = 0x4AF5
ciphertext1, round_keys1 = mini_aes.encrypt(plaintext1, key1)
decrypted1 = mini_aes.decrypt(ciphertext1, round_keys1)
```
**Penjelasan:** Encrypt dan decrypt untuk memastikan kebenaran implementasi.

### 1.9 Output Proses per Round
```python
print(f"Round {r} after SubNibbles: {self._state_to_hex(state)}")
```
**Penjelasan:** Menampilkan keadaan state setelah tiap operasi dalam ronde.

---

## 2. Spesifikasi Tambahan (18-20 poin)

### 2.1 Implementasi Dekripsi
```python
def decrypt(self, ciphertext, round_keys):
```
**Penjelasan:** Menggunakan operasi inverse untuk mengembalikan ciphertext menjadi plaintext.

### 2.2 Analisis Avalanche Effect
```python
def analyze_avalanche(self, plaintext, key, modify_plaintext=True, bit_position=0):
```
**Penjelasan:** Menghitung berapa banyak bit yang berubah ketika satu bit diubah di plaintext atau key.

### 2.3 Mode Operasi ECB dan CBC
```python
def encrypt_ecb(self, plaintext_blocks, key):
def decrypt_ecb(self, ciphertext_blocks, key):
def encrypt_cbc(self, plaintext_blocks, key, iv):
def decrypt_cbc(self, ciphertext_blocks, key, iv):
```
**Penjelasan:** Implementasi mode operasi blok ECB dan CBC, mendukung teks lebih panjang.

---

# Kesimpulan
Implementasi Mini-AES ini berhasil memenuhi seluruh spesifikasi dasar dan hampir seluruh spesifikasi tambahan, kecuali fitur Export/Import file yang belum diimplementasikan. Fitur tambahan seperti mode operasi blok dan analisis avalanche telah berhasil diselesaikan, memberikan gambaran yang komprehensif tentang dasar-dasar enkripsi blok modern.

---

