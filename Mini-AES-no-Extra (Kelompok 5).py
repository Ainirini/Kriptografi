"""
Mini-AES Implementation for Cryptography Course
==============================================

This file implements a 16-bit version of AES (Advanced Encryption Standard) called Mini-AES.
It includes all core AES operations scaled down to work with 16-bit blocks:
- SubNibbles (4-bit S-Box substitution)
- ShiftRows (shifting of rows in the state matrix)
- MixColumns (column mixing in GF(2^4))
- AddRoundKey (XOR with round keys)
- Key Expansion (generation of round keys)

The implementation uses a 2x2 state matrix where each element is a 4-bit nibble.
"""

import numpy as np

class MiniAES:
    """
    Mini-AES cipher implementation with 16-bit block size and 16-bit key.
    
    Attributes:
        SBOX: Substitution box for the SubNibbles operation
        INV_SBOX: Inverse substitution box for decryption
    """
    
    # S-Box for SubNibbles operation (4-bit)
    # This is a simplified version of the AES S-Box for 4-bit values
    SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
    
    # Inverse S-Box for decryption
    # This is the inverse mapping of the S-Box above
    INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]
    
    def __init__(self):
        """Initialize the Mini-AES cipher."""
        pass
    
    # ========== Galois Field Operations ==========
    
    def gf_mult(self, a, b):
        """
        Multiply two numbers in the Galois Field GF(2^4).
        
        Uses x^4 + x + 1 as the irreducible polynomial for GF(2^4).
        This implements polynomial multiplication followed by reduction.
        
        Args:
            a (int): First 4-bit number
            b (int): Second 4-bit number
            
        Returns:
            int: Result of multiplication in GF(2^4)
        """
        result = 0
        for i in range(4):  # Each nibble has 4 bits
            if (b & 1) == 1:  # If lowest bit of b is set
                result ^= a    # XOR result with a (polynomial addition)
            
            # Check if highest bit is set before shift (for reduction)
            high_bit = a & 0x8
            a <<= 1           # Left shift a (multiply by x)
            
            if high_bit == 0x8:  # If we need to reduce
                a ^= 0x13     # XOR with the irreducible polynomial x^4 + x + 1 (0b10011)
            
            a &= 0xF   # Keep only 4 bits
            b >>= 1     # Right shift b (divide by x)
            
        return result
    
    # ========== Core AES Operations ==========
    
    def sub_nibbles(self, state):
        """
        Apply S-Box substitution to each nibble in the state matrix.
        
        This corresponds to the SubBytes operation in AES.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix with 4-bit values
            
        Returns:
            numpy.ndarray: State matrix after substitution
        """
        result = np.zeros_like(state)
        for i in range(2):
            for j in range(2):
                result[i, j] = self.SBOX[int(state[i, j])]
        return result
    
    def inv_sub_nibbles(self, state):
        """
        Apply inverse S-Box substitution for decryption.
        
        This corresponds to the InvSubBytes operation in AES.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix with 4-bit values
            
        Returns:
            numpy.ndarray: State matrix after inverse substitution
        """
        result = np.zeros_like(state)
        for i in range(2):
            for j in range(2):
                result[i, j] = self.INV_SBOX[int(state[i, j])]
        return result
    
    def shift_rows(self, state):
        """
        Shift rows operation - shifts second row by 1 position.
        
        In Mini-AES with a 2x2 matrix, only the second row is shifted.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            
        Returns:
            numpy.ndarray: State matrix after row shifting
        """
        result = state.copy()
        # Swap elements in the second row - for a 2x2 matrix, this is simple
        result[1, 0], result[1, 1] = state[1, 1], state[1, 0]
        return result
    
    def inv_shift_rows(self, state):
        """
        Inverse shift rows operation for decryption.
        
        In a 2x2 matrix, this is identical to the forward operation.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            
        Returns:
            numpy.ndarray: State matrix after inverse row shifting
        """
        # For 2x2 matrix, inverse shift is the same as shift
        return self.shift_rows(state)
    
    def mix_columns(self, state):
        """
        Mix Columns operation applying a linear transformation on each column.
        
        In Mini-AES, the MixColumns matrix is [[1, 4], [4, 1]] in GF(2^4).
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            
        Returns:
            numpy.ndarray: State matrix after column mixing
        """
        result = np.zeros_like(state)
        
        # Apply MixColumns to each column
        for j in range(2):  # For each column
            # Matrix multiplication in GF(2^4)
            # [1 4] × [a] = [1×a + 4×b]
            # [4 1]   [b]   [4×a + 1×b]
            result[0, j] = self.gf_mult(1, state[0, j]) ^ self.gf_mult(4, state[1, j])
            result[1, j] = self.gf_mult(4, state[0, j]) ^ self.gf_mult(1, state[1, j])
        
        return result
    
    def inv_mix_columns(self, state):
        """
        Inverse Mix Columns operation for decryption.
        
        In Mini-AES, the inverse MixColumns matrix is [[9, 2], [2, 9]] in GF(2^4).
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            
        Returns:
            numpy.ndarray: State matrix after inverse column mixing
        """
        result = np.zeros_like(state)
        
        # Apply inverse MixColumns to each column
        for j in range(2):  # For each column
            # Inverse matrix multiplication in GF(2^4)
            # [9 2] × [a] = [9×a + 2×b]
            # [2 9]   [b]   [2×a + 9×b]
            result[0, j] = self.gf_mult(9, state[0, j]) ^ self.gf_mult(2, state[1, j])
            result[1, j] = self.gf_mult(2, state[0, j]) ^ self.gf_mult(9, state[1, j])
        
        return result
    
    def add_round_key(self, state, round_key):
        """
        Add Round Key operation - XOR the state with the round key.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            round_key (numpy.ndarray): 2x2 round key matrix
            
        Returns:
            numpy.ndarray: State matrix after adding round key
        """
        # Bitwise XOR of state with round key
        return np.bitwise_xor(state, round_key)
    
    # ========== Key Expansion ==========
    
    def key_expansion(self, key):
        """
        Generate round keys from the initial key.
        
        For 3 rounds of Mini-AES, we need to generate 4 round keys total
        (including the initial key).
        
        Args:
            key (numpy.ndarray): 2x2 initial key matrix
            
        Returns:
            list: List of round keys for each round
        """
        # Number of rounds in Mini-AES
        num_rounds = 3
        
        # Array to store round keys (including initial key)
        round_keys = [None] * (num_rounds + 1)
        round_keys[0] = key.copy()
        
        # Round constants (RCON) for each round
        # These are similar to AES RCON but adapted for 4-bit
        rcon = [0x1, 0x2, 0x4]  # Values increase by powers of 2
        
        for i in range(1, num_rounds + 1):
            # Start with previous round key
            prev_key = round_keys[i-1]
            new_key = np.zeros_like(prev_key)
            
            # 1. RotWord: Rotate the second column
            # 2. SubWord: Apply S-Box to the rotated column
            rotated_col = np.array([prev_key[1, 1], prev_key[0, 1]])
            subbed_col = np.array([self.SBOX[int(rotated_col[0])], self.SBOX[int(rotated_col[1])]])
            
            # 3. XOR operations to generate new key columns
            # First column = prev_first_column XOR SubWord(RotWord(prev_second_column)) XOR RCON
            new_key[0, 0] = prev_key[0, 0] ^ subbed_col[0] ^ rcon[i-1]
            new_key[1, 0] = prev_key[1, 0] ^ subbed_col[1]
            
            # Second column = prev_second_column XOR new_first_column
            new_key[0, 1] = prev_key[0, 1] ^ new_key[0, 0]
            new_key[1, 1] = prev_key[1, 1] ^ new_key[1, 0]
            
            round_keys[i] = new_key
        
        return round_keys
    
    # ========== Encryption and Decryption ==========
    
    def encrypt(self, plaintext, key):
        """
        Encrypt a 16-bit plaintext using Mini-AES.
        
        Args:
            plaintext (int): 16-bit plaintext as an integer
            key (int): 16-bit key as an integer
            
        Returns:
            tuple: (ciphertext as int, list of round keys)
        """
        # Convert 16-bit plaintext to 2x2 state matrix of nibbles
        state = self._bits_to_state(plaintext)
        
        # Convert 16-bit key to 2x2 key matrix of nibbles
        key_matrix = self._bits_to_state(key)
        
        # Generate round keys
        round_keys = self.key_expansion(key_matrix)
        
        # Print initial state
        print(f"Initial state: {self._state_to_hex(state)}")
        
        # Initial round - just add round key
        state = self.add_round_key(state, round_keys[0])
        print(f"After Initial AddRoundKey: {self._state_to_hex(state)}")
        
        # Main rounds (1 and 2)
        for r in range(1, 3):
            # SubNibbles
            state = self.sub_nibbles(state)
            print(f"Round {r} after SubNibbles: {self._state_to_hex(state)}")
            
            # ShiftRows
            state = self.shift_rows(state)
            print(f"Round {r} after ShiftRows: {self._state_to_hex(state)}")
            
            # MixColumns
            state = self.mix_columns(state)
            print(f"Round {r} after MixColumns: {self._state_to_hex(state)}")
            
            # AddRoundKey
            state = self.add_round_key(state, round_keys[r])
            print(f"Round {r} after AddRoundKey: {self._state_to_hex(state)}")
        
        # Final round (round 3) - no MixColumns
        # SubNibbles
        state = self.sub_nibbles(state)
        print(f"Final Round after SubNibbles: {self._state_to_hex(state)}")
        
        # ShiftRows
        state = self.shift_rows(state)
        print(f"Final Round after ShiftRows: {self._state_to_hex(state)}")
        
        # AddRoundKey
        state = self.add_round_key(state, round_keys[3])
        print(f"Final Output: {self._state_to_hex(state)}")
        
        # Convert state back to 16-bit ciphertext
        ciphertext = self._state_to_bits(state)
        
        return ciphertext, round_keys
    
    def decrypt(self, ciphertext, round_keys):
        """
        Decrypt a 16-bit ciphertext using Mini-AES.
        
        Args:
            ciphertext (int): 16-bit ciphertext as an integer
            round_keys (list): List of round keys generated during encryption
            
        Returns:
            int: Decrypted plaintext as an integer
        """
        # Convert 16-bit ciphertext to 2x2 state matrix of nibbles
        state = self._bits_to_state(ciphertext)
        
        print(f"Initial state (ciphertext): {self._state_to_hex(state)}")
        
        # Final round - reverse operations (no MixColumns)
        # AddRoundKey (with last round key)
        state = self.add_round_key(state, round_keys[3])
        print(f"After undoing final AddRoundKey: {self._state_to_hex(state)}")
        
        # InvShiftRows
        state = self.inv_shift_rows(state)
        print(f"After InvShiftRows: {self._state_to_hex(state)}")
        
        # InvSubNibbles
        state = self.inv_sub_nibbles(state)
        print(f"After InvSubNibbles: {self._state_to_hex(state)}")
        
        # Main rounds in reverse (2 down to 1)
        for r in range(2, 0, -1):
            # AddRoundKey
            state = self.add_round_key(state, round_keys[r])
            print(f"Round {r} after AddRoundKey: {self._state_to_hex(state)}")
            
            # InvMixColumns
            state = self.inv_mix_columns(state)
            print(f"Round {r} after InvMixColumns: {self._state_to_hex(state)}")
            
            # InvShiftRows
            state = self.inv_shift_rows(state)
            print(f"Round {r} after InvShiftRows: {self._state_to_hex(state)}")
            
            # InvSubNibbles
            state = self.inv_sub_nibbles(state)
            print(f"Round {r} after InvSubNibbles: {self._state_to_hex(state)}")
        
        # Initial round - just add round key
        state = self.add_round_key(state, round_keys[0])
        print(f"Final decrypted plaintext: {self._state_to_hex(state)}")
        
        # Convert state back to 16-bit plaintext
        plaintext = self._state_to_bits(state)
        
        return plaintext
    
    # ========== Block Cipher Modes of Operation ==========
    
    def encrypt_ecb(self, plaintext_blocks, key):
        """
        Encrypt using Electronic Codebook (ECB) mode.
        
        Args:
            plaintext_blocks (list): List of 16-bit plaintext blocks
            key (int): 16-bit key
            
        Returns:
            list: List of encrypted 16-bit blocks
        """
        print("\n=== ECB Mode Encryption ===")
        # Generate key schedule once
        key_matrix = self._bits_to_state(key)
        round_keys = self.key_expansion(key_matrix)
        
        ciphertext_blocks = []
        for i, block in enumerate(plaintext_blocks):
            print(f"\nEncrypting Block {i+1}: 0x{block:04X}")
            ciphertext, _ = self.encrypt(block, key)
            ciphertext_blocks.append(ciphertext)
            print(f"Encrypted Block {i+1}: 0x{ciphertext:04X}")
        
        return ciphertext_blocks
    
    def decrypt_ecb(self, ciphertext_blocks, key):
        """
        Decrypt using Electronic Codebook (ECB) mode.
        
        Args:
            ciphertext_blocks (list): List of 16-bit ciphertext blocks
            key (int): 16-bit key
            
        Returns:
            list: List of decrypted 16-bit blocks
        """
        print("\n=== ECB Mode Decryption ===")
        # Generate key schedule once
        key_matrix = self._bits_to_state(key)
        round_keys = self.key_expansion(key_matrix)
        
        plaintext_blocks = []
        for i, block in enumerate(ciphertext_blocks):
            print(f"\nDecrypting Block {i+1}: 0x{block:04X}")
            plaintext = self.decrypt(block, round_keys)
            plaintext_blocks.append(plaintext)
            print(f"Decrypted Block {i+1}: 0x{plaintext:04X}")
        
        return plaintext_blocks
    
    def encrypt_cbc(self, plaintext_blocks, key, iv):
        """
        Encrypt using Cipher Block Chaining (CBC) mode.
        
        Args:
            plaintext_blocks (list): List of 16-bit plaintext blocks
            key (int): 16-bit key
            iv (int): 16-bit initialization vector
            
        Returns:
            list: List of encrypted 16-bit blocks
        """
        print("\n=== CBC Mode Encryption ===")
        # Generate key schedule once
        key_matrix = self._bits_to_state(key)
        round_keys = self.key_expansion(key_matrix)
        
        ciphertext_blocks = []
        previous_block = iv
        
        for i, block in enumerate(plaintext_blocks):
            print(f"\nEncrypting Block {i+1}: 0x{block:04X}")
            print(f"Previous Block/IV: 0x{previous_block:04X}")
            
            # XOR with previous ciphertext block or IV
            xored_block = block ^ previous_block
            print(f"After XOR: 0x{xored_block:04X}")
            
            # Encrypt
            ciphertext, _ = self.encrypt(xored_block, key)
            ciphertext_blocks.append(ciphertext)
            
            # Current ciphertext becomes the next "previous block"
            previous_block = ciphertext
            
            print(f"Encrypted Block {i+1}: 0x{ciphertext:04X}")
        
        return ciphertext_blocks
    
    def decrypt_cbc(self, ciphertext_blocks, key, iv):
        """
        Decrypt using Cipher Block Chaining (CBC) mode.
        
        Args:
            ciphertext_blocks (list): List of 16-bit ciphertext blocks
            key (int): 16-bit key
            iv (int): 16-bit initialization vector
            
        Returns:
            list: List of decrypted 16-bit blocks
        """
        print("\n=== CBC Mode Decryption ===")
        # Generate key schedule once
        key_matrix = self._bits_to_state(key)
        round_keys = self.key_expansion(key_matrix)
        
        plaintext_blocks = []
        previous_block = iv
        
        for i, block in enumerate(ciphertext_blocks):
            print(f"\nDecrypting Block {i+1}: 0x{block:04X}")
            
            # Decrypt
            decrypted = self.decrypt(block, round_keys)
            print(f"After Decryption: 0x{decrypted:04X}")
            
            # XOR with previous ciphertext block or IV
            plaintext = decrypted ^ previous_block
            plaintext_blocks.append(plaintext)
            
            print(f"Previous Block/IV: 0x{previous_block:04X}")
            print(f"Decrypted Block {i+1}: 0x{plaintext:04X}")
            
            # Current ciphertext becomes the next "previous block"
            previous_block = block
        
        return plaintext_blocks
    
    # ========== Utility Methods ==========
    
    def _bits_to_state(self, bits):
        """
        Convert 16-bit integer to 2x2 state matrix with 4-bit nibbles.
        
        Layout (bit positions):
        [ 15-12, 11-8 ]
        [ 7-4,   3-0  ]
        
        Args:
            bits (int): 16-bit integer
            
        Returns:
            numpy.ndarray: 2x2 state matrix
        """
        state = np.zeros((2, 2), dtype=np.uint8)
        state[0, 0] = (bits >> 12) & 0xF  # Most significant nibble
        state[0, 1] = (bits >> 8) & 0xF
        state[1, 0] = (bits >> 4) & 0xF
        state[1, 1] = bits & 0xF          # Least significant nibble
        return state
    
    def _state_to_bits(self, state):
        """
        Convert 2x2 state matrix with nibbles back to 16-bit integer.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            
        Returns:
            int: 16-bit integer representation
        """
        bits = 0
        bits |= int(state[0, 0]) << 12
        bits |= int(state[0, 1]) << 8
        bits |= int(state[1, 0]) << 4
        bits |= int(state[1, 1])
        return bits
    
    def _state_to_hex(self, state):
        """
        Convert state matrix to hexadecimal string for display.
        
        Args:
            state (numpy.ndarray): 2x2 state matrix
            
        Returns:
            str: Hexadecimal representation
        """
        bits = self._state_to_bits(state)
        return f"0x{bits:04X}"
    
    # ========== Analysis Methods ==========
    
    def analyze_avalanche(self, plaintext, key, modify_plaintext=True, bit_position=0):
        """
        Analyze the avalanche effect by flipping a bit and comparing outputs.
        
        Args:
            plaintext (int): Original 16-bit plaintext
            key (int): Original 16-bit key
            modify_plaintext (bool): If True, modify plaintext; otherwise modify key
            bit_position (int): Position of bit to flip (0-15)
            
        Returns:
            tuple: (original_ciphertext, modified_ciphertext, differing_bits)
        """
        if bit_position < 0 or bit_position > 15:
            raise ValueError("Bit position must be between 0 and 15")
        
        # First encryption with original values
        print("\n=== Avalanche Effect Analysis ===")
        print(f"Original Plaintext: 0x{plaintext:04X}")
        print(f"Original Key: 0x{key:04X}")
        
        original_cipher, original_keys = self.encrypt(plaintext, key)
        print(f"Original Ciphertext: 0x{original_cipher:04X}")
        
        # Flip the specified bit
        bit_mask = 1 << bit_position
        if modify_plaintext:
            modified_plaintext = plaintext ^ bit_mask
            modified_key = key
            print(f"\nModified Plaintext (bit {bit_position}): 0x{modified_plaintext:04X}")
            print(f"Key: 0x{key:04X}")
        else:
            modified_plaintext = plaintext
            modified_key = key ^ bit_mask
            print(f"\nPlaintext: 0x{plaintext:04X}")
            print(f"Modified Key (bit {bit_position}): 0x{modified_key:04X}")
        
        # Second encryption with modified value
        modified_cipher, _ = self.encrypt(modified_plaintext, modified_key)
        print(f"Modified Ciphertext: 0x{modified_cipher:04X}")
        
        # Calculate difference
        diff = original_cipher ^ modified_cipher
        diff_bin = bin(diff)[2:].zfill(16)
        differing_bits = diff_bin.count('1')
        
        print(f"\nDifference (XOR): 0x{diff:04X}")
        print(f"Difference (binary): {diff_bin}")
        print(f"Number of differing bits: {differing_bits} out of 16 ({differing_bits/16*100:.1f}%)")
        
        return original_cipher, modified_cipher, differing_bits


# ========== Main Function with Test Cases ==========

def main():
    """Run test cases for Mini-AES implementation."""
    mini_aes = MiniAES()
    
    print("=" * 60)
    print("MINI-AES IMPLEMENTATION TEST")
    print("=" * 60)
    
    # Test case 1: Basic encryption/decryption
    plaintext1 = 0xABCD
    key1 = 0x4AF5
    
    print("\nTest Case 1: Basic Encryption/Decryption")
    print(f"Plaintext: 0x{plaintext1:04X}")
    print(f"Key: 0x{key1:04X}")
    
    # Encrypt
    print("\n--- Encryption ---")
    ciphertext1, round_keys1 = mini_aes.encrypt(plaintext1, key1)
    print(f"\nFinal ciphertext: 0x{ciphertext1:04X}")
    
    # Decrypt
    print("\n--- Decryption ---")
    decrypted1 = mini_aes.decrypt(ciphertext1, round_keys1)
    print(f"\nDecrypted plaintext: 0x{decrypted1:04X}")
    print(f"Decryption Successful: {plaintext1 == decrypted1}")
    
    # Test case 2: Different plaintext/key
    plaintext2 = 0x1234
    key2 = 0x5678
    
    print("\n" + "=" * 40)
    print("\nTest Case 2: Different Plaintext/Key")
    print(f"Plaintext: 0x{plaintext2:04X}")
    print(f"Key: 0x{key2:04X}")
    
    # Encrypt
    print("\n--- Encryption ---")
    ciphertext2, round_keys2 = mini_aes.encrypt(plaintext2, key2)
    print(f"\nFinal ciphertext: 0x{ciphertext2:04X}")
    
    # Decrypt
    print("\n--- Decryption ---")
    decrypted2 = mini_aes.decrypt(ciphertext2, round_keys2)
    print(f"\nDecrypted plaintext: 0x{decrypted2:04X}")
    print(f"Decryption Successful: {plaintext2 == decrypted2}")
    
    # Test case 3: Avalanche effect (flipping a bit in plaintext)
    print("\n" + "=" * 40)
    print("\nTest Case 3: Avalanche Effect Analysis")
    mini_aes.analyze_avalanche(plaintext1, key1, modify_plaintext=True, bit_position=0)
    
    # Block mode test: ECB
    print("\n" + "=" * 40)
    print("\nTest Case 4: ECB Block Mode")
    plaintext_blocks = [0xABCD, 0x1234, 0x5678, 0x90EF]
    key4 = 0xDEAD
    
    print(f"Plaintext blocks: {[hex(b) for b in plaintext_blocks]}")
    print(f"Key: 0x{key4:04X}")
    
    # Encrypt with ECB
    ciphertext_blocks = mini_aes.encrypt_ecb(plaintext_blocks, key4)
    print(f"Ciphertext blocks: {[hex(b) for b in ciphertext_blocks]}")
    
    # Decrypt with ECB
    decrypted_blocks = mini_aes.decrypt_ecb(ciphertext_blocks, key4)
    print(f"Decrypted blocks: {[hex(b) for b in decrypted_blocks]}")
    print(f"Decryption Successful: {plaintext_blocks == decrypted_blocks}")
    
    # Block mode test: CBC
    print("\n" + "=" * 40)
    print("\nTest Case 5: CBC Block Mode")
    iv = 0x1111
    
    print(f"Plaintext blocks: {[hex(b) for b in plaintext_blocks]}")
    print(f"Key: 0x{key4:04X}")
    print(f"IV: 0x{iv:04X}")
    
    # Encrypt with CBC
    cbc_ciphertext_blocks = mini_aes.encrypt_cbc(plaintext_blocks, key4, iv)
    print(f"CBC Ciphertext blocks: {[hex(b) for b in cbc_ciphertext_blocks]}")
    
    # Decrypt with CBC
    cbc_decrypted_blocks = mini_aes.decrypt_cbc(cbc_ciphertext_blocks, key4, iv)
    print(f"CBC Decrypted blocks: {[hex(b) for b in cbc_decrypted_blocks]}")
    print(f"CBC Decryption Successful: {plaintext_blocks == cbc_decrypted_blocks}")


if __name__ == "__main__":
    main()