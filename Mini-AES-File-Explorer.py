"""
Mini-AES GUI Implementation

This file implements a graphical user interface for the Mini-AES cipher.
It allows users to:
- Encrypt and decrypt using Mini-AES
- Load plaintext/key/ciphertext from files using file explorer
- Save results to files in the application directory
- Choose between different encryption modes (ECB/CBC)
- Visualize the encryption/decryption process

Features:
- File explorer for selecting input files
- Automatic file naming for encrypted/decrypted files
- Key prompt when decrypting files with "Encrypted" in the name
- Detailed logging of encryption/decryption process
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import os
import sys
from datetime import datetime

# Assuming the MiniAES class is defined in a module named mini_aes
from mini_aes import MiniAES

class MiniAESGUI:
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("Mini-AES Encryption Tool")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Initialize Mini-AES instance
        self.mini_aes = MiniAES(log_to_file=True)
        
        # Create the main frame
        self.create_widgets()
        
    def create_widgets(self):
        """Create the GUI widgets."""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.single_block_tab = ttk.Frame(self.notebook)
        self.block_mode_tab = ttk.Frame(self.notebook)
        self.file_operations_tab = ttk.Frame(self.notebook)
        self.avalanche_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.single_block_tab, text="Single Block")
        self.notebook.add(self.block_mode_tab, text="Block Mode")
        self.notebook.add(self.file_operations_tab, text="File Operations")
        self.notebook.add(self.avalanche_tab, text="Analysis")
        
        # Set up tabs
        self.setup_single_block_tab()
        self.setup_block_mode_tab()
        self.setup_file_operations_tab()
        self.setup_avalanche_tab()
    
    def setup_single_block_tab(self):
        """Set up the single block encryption/decryption tab."""
        frame = self.single_block_tab
        
        # Create input frames
        input_frame = ttk.LabelFrame(frame, text="Input")
        input_frame.pack(fill=tk.X, expand=False, padx=10, pady=10)
        
        # Plaintext input
        ttk.Label(input_frame, text="Plaintext (hex):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.plaintext_var = tk.StringVar(value="ABCD")
        plaintext_entry = ttk.Entry(input_frame, textvariable=self.plaintext_var)
        plaintext_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Key input
        ttk.Label(input_frame, text="Key (hex):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_var = tk.StringVar(value="4AF5")
        key_entry = ttk.Entry(input_frame, textvariable=self.key_var)
        key_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Key selection combobox
        ttk.Label(input_frame, text="Select Key:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.key_combo = ttk.Combobox(input_frame, width=10)
        self.key_combo['values'] = ('4AF5', '5678', 'DEAD', 'C0DE', 'FACE', 'CAFE', 'BEEF', 'BABE')
        self.key_combo.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        self.key_combo.bind('<<ComboboxSelected>>', lambda e: self.key_var.set(self.key_combo.get()))
        
        # Ciphertext output
        ttk.Label(input_frame, text="Ciphertext (hex):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.ciphertext_var = tk.StringVar()
        ciphertext_entry = ttk.Entry(input_frame, textvariable=self.ciphertext_var, state="readonly")
        ciphertext_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Buttons frame
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, expand=False, padx=10, pady=5)
        
        # Encrypt and decrypt buttons
        encrypt_btn = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_single_block)
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        decrypt_btn = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_single_block)
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Save results button
        save_btn = ttk.Button(button_frame, text="Save Results", command=self.save_single_block_results)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_single_block)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(frame, text="Encryption/Decryption Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.single_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20)
        self.single_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_block_mode_tab(self):
        """Set up the block mode encryption/decryption tab."""
        frame = self.block_mode_tab
        
        # Mode selection frame
        mode_frame = ttk.LabelFrame(frame, text="Block Cipher Mode")
        mode_frame.pack(fill=tk.X, expand=False, padx=10, pady=10)
        
        # Mode selection radio buttons
        self.mode_var = tk.StringVar(value="ECB")
        ecb_radio = ttk.Radiobutton(mode_frame, text="Electronic Codebook (ECB)", variable=self.mode_var, value="ECB")
        ecb_radio.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        cbc_radio = ttk.Radiobutton(mode_frame, text="Cipher Block Chaining (CBC)", variable=self.mode_var, value="CBC")
        cbc_radio.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # IV input for CBC
        ttk.Label(mode_frame, text="IV (hex, for CBC):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.iv_var = tk.StringVar(value="1111")
        iv_entry = ttk.Entry(mode_frame, textvariable=self.iv_var)
        iv_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Input frame
        input_frame = ttk.LabelFrame(frame, text="Input")
        input_frame.pack(fill=tk.X, expand=False, padx=10, pady=10)
        
        # Key input
        ttk.Label(input_frame, text="Key (hex):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.block_key_var = tk.StringVar(value="DEAD")
        key_entry = ttk.Entry(input_frame, textvariable=self.block_key_var)
        key_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Plaintext blocks input
        ttk.Label(input_frame, text="Plaintext Blocks (hex, comma separated):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.plaintext_blocks_var = tk.StringVar(value="ABCD,1234,5678,90EF")
        plaintext_blocks_entry = ttk.Entry(input_frame, textvariable=self.plaintext_blocks_var)
        plaintext_blocks_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W + tk.E)
        
        # Ciphertext blocks output
        ttk.Label(input_frame, text="Ciphertext Blocks (hex):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.ciphertext_blocks_var = tk.StringVar()
        ciphertext_blocks_entry = ttk.Entry(input_frame, textvariable=self.ciphertext_blocks_var, state="readonly")
        ciphertext_blocks_entry.grid(row=2, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W + tk.E)
        
        # Buttons frame
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, expand=False, padx=10, pady=5)
        
        # Encrypt and decrypt buttons
        encrypt_btn = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_block_mode)
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        decrypt_btn = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_block_mode)
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Save results button
        save_btn = ttk.Button(button_frame, text="Save Results", command=self.save_block_mode_results)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_block_mode)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(frame, text="Block Mode Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.block_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20)
        self.block_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_file_operations_tab(self):
        """Set up the file operations tab."""
        frame = self.file_operations_tab
        
        # File operations frame
        file_frame = ttk.LabelFrame(frame, text="File Operations")
        file_frame.pack(fill=tk.X, expand=False, padx=10, pady=10)
        
        # File operation type
        ttk.Label(file_frame, text="Operation:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.file_op_var = tk.StringVar(value="encrypt")
        encrypt_radio = ttk.Radiobutton(file_frame, text="Encrypt File", variable=self.file_op_var, value="encrypt")
        encrypt_radio.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        decrypt_radio = ttk.Radiobutton(file_frame, text="Decrypt File", variable=self.file_op_var, value="decrypt")
        decrypt_radio.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        
        # Load from file
        ttk.Label(file_frame, text="Select file:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.load_file_path_var = tk.StringVar()
        load_file_entry = ttk.Entry(file_frame, textvariable=self.load_file_path_var, width=40)
        load_file_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        load_file_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_load_file)
        load_file_btn.grid(row=1, column=2, padx=5, pady=5)
        
        # Key input (for encryption and decryption)
        ttk.Label(file_frame, text="Key (hex):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.file_key_var = tk.StringVar(value="4AF5")
        key_entry = ttk.Entry(file_frame, textvariable=self.file_key_var)
        key_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Block mode selection
        ttk.Label(file_frame, text="Block Mode:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.file_mode_var = tk.StringVar(value="ECB")
        ecb_radio = ttk.Radiobutton(file_frame, text="ECB", variable=self.file_mode_var, value="ECB")
        ecb_radio.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        cbc_radio = ttk.Radiobutton(file_frame, text="CBC", variable=self.file_mode_var, value="CBC")
        cbc_radio.grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        
        # IV input for CBC
        ttk.Label(file_frame, text="IV (hex, for CBC):").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.file_iv_var = tk.StringVar(value="1111")
        iv_entry = ttk.Entry(file_frame, textvariable=self.file_iv_var)
        iv_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Process file button
        process_btn = ttk.Button(file_frame, text="Process File", command=self.process_file)
        process_btn.grid(row=5, column=0, columnspan=3, padx=5, pady=10, sticky=tk.W+tk.E)
        
        # Data display
        data_frame = ttk.LabelFrame(frame, text="File Processing Results")
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.file_data_display = scrolledtext.ScrolledText(data_frame, wrap=tk.WORD, width=80, height=20)
        self.file_data_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_avalanche_tab(self):
        """Set up the avalanche analysis tab."""
        frame = self.avalanche_tab
        
        # Avalanche test input frame
        test_frame = ttk.LabelFrame(frame, text="Avalanche Effect Test")
        test_frame.pack(fill=tk.X, expand=False, padx=10, pady=10)
        
        # Plaintext input
        ttk.Label(test_frame, text="Plaintext (hex):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.av_plaintext_var = tk.StringVar(value="ABCD")
        plaintext_entry = ttk.Entry(test_frame, textvariable=self.av_plaintext_var)
        plaintext_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Key input
        ttk.Label(test_frame, text="Key (hex):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.av_key_var = tk.StringVar(value="4AF5")
        key_entry = ttk.Entry(test_frame, textvariable=self.av_key_var)
        key_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Modification selection
        ttk.Label(test_frame, text="Modify:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.modify_var = tk.StringVar(value="plaintext")
        plaintext_radio = ttk.Radiobutton(test_frame, text="Plaintext", variable=self.modify_var, value="plaintext")
        plaintext_radio.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        key_radio = ttk.Radiobutton(test_frame, text="Key", variable=self.modify_var, value="key")
        key_radio.grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        
        # Bit position selection
        ttk.Label(test_frame, text="Bit position to flip (0-15):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.bit_position_var = tk.StringVar(value="0")
        bit_spinbox = ttk.Spinbox(test_frame, from_=0, to=15, textvariable=self.bit_position_var, width=5)
        bit_spinbox.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Run button
        run_btn = ttk.Button(test_frame, text="Run Avalanche Test", command=self.run_avalanche_test)
        run_btn.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        
        # Save results button
        save_btn = ttk.Button(test_frame, text="Save Results", command=self.save_avalanche_results)
        save_btn.grid(row=4, column=2, padx=5, pady=5)
        
        # Results display
        results_frame = ttk.LabelFrame(frame, text="Avalanche Test Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.avalanche_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=80, height=20)
        self.avalanche_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # ========== Single Block Tab Functions ==========
    
    def encrypt_single_block(self):
        """Encrypt a single block of plaintext."""
        try:
            plaintext = int(self.plaintext_var.get(), 16)
            key = int(self.key_var.get(), 16)
            
            # Capture log output
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                ciphertext, _ = self.mini_aes.encrypt(plaintext, key)
            
            log_output = f.getvalue()
            
            # Update ciphertext display
            self.ciphertext_var.set(f"{ciphertext:04X}")
            
            # Update log display
            self.single_log.delete(1.0, tk.END)
            self.single_log.insert(tk.END, log_output)
            
            # Auto-scroll to the bottom
            self.single_log.see(tk.END)
            
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {str(e)}")
    
    def decrypt_single_block(self):
        """Decrypt a single block of ciphertext."""
        try:
            if not self.ciphertext_var.get():
                messagebox.showwarning("Warning", "Please encrypt first or enter a ciphertext value.")
                return
                
            ciphertext = int(self.ciphertext_var.get(), 16)
            key = int(self.key_var.get(), 16)
            
            # Generate key schedule
            key_matrix = self.mini_aes._bits_to_state(key)
            round_keys = self.mini_aes.key_expansion(key_matrix)
            
            # Capture log output
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                plaintext = self.mini_aes.decrypt(ciphertext, round_keys)
            
            log_output = f.getvalue()
            
            # Update plaintext display
            self.plaintext_var.set(f"{plaintext:04X}")
            
            # Update log display
            self.single_log.delete(1.0, tk.END)
            self.single_log.insert(tk.END, log_output)
            
            # Auto-scroll to the bottom
            self.single_log.see(tk.END)
            
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {str(e)}")
    
    def save_single_block_results(self):
        """Save the single block encryption results to a file."""
        try:
            if not self.ciphertext_var.get():
                messagebox.showwarning("Warning", "Please encrypt first.")
                return
                
            plaintext = int(self.plaintext_var.get(), 16)
            key = int(self.key_var.get(), 16)
            ciphertext = int(self.ciphertext_var.get(), 16)
            
            # Ask user for file location and format
            file_types = [('Text files', '*.txt'), ('CSV files', '*.csv'), ('All files', '*.*')]
            file_path = filedialog.asksaveasfilename(filetypes=file_types, defaultextension=".txt")
            
            if file_path:
                if file_path.endswith('.csv'):
                    self.mini_aes.save_encryption_data(file_path, plaintext, key, ciphertext, mode="csv")
                else:
                    self.mini_aes.save_encryption_data(file_path, plaintext, key, ciphertext, mode="txt")
                
                messagebox.showinfo("Success", f"Results saved to {file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error saving results: {str(e)}")
    
    def clear_single_block(self):
        """Clear the single block tab inputs and outputs."""
        self.plaintext_var.set("ABCD")
        self.key_var.set("4AF5")
        self.ciphertext_var.set("")
        self.single_log.delete(1.0, tk.END)
    
    # ========== Block Mode Tab Functions ==========
    
    def encrypt_block_mode(self):
        """Encrypt using block cipher mode."""
        try:
            # Parse plaintext blocks
            plaintext_blocks_hex = self.plaintext_blocks_var.get().split(',')
            plaintext_blocks = [int(block.strip(), 16) for block in plaintext_blocks_hex]
            
            key = int(self.block_key_var.get(), 16)
            mode = self.mode_var.get()
            
            # Capture log output
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                if mode == "ECB":
                    ciphertext_blocks = self.mini_aes.encrypt_ecb(plaintext_blocks, key)
                else:  # CBC mode
                    iv = int(self.iv_var.get(), 16)
                    ciphertext_blocks = self.mini_aes.encrypt_cbc(plaintext_blocks, key, iv)
            
            log_output = f.getvalue()
            
            # Format ciphertext blocks for display
            ciphertext_blocks_hex = [f"{block:04X}" for block in ciphertext_blocks]
            self.ciphertext_blocks_var.set(','.join(ciphertext_blocks_hex))
            
            # Update log display
            self.block_log.delete(1.0, tk.END)
            self.block_log.insert(tk.END, log_output)
            
            # Auto-scroll to the bottom
            self.block_log.see(tk.END)
            
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {str(e)}")
    
    def decrypt_block_mode(self):
        """Decrypt using block cipher mode."""
        try:
            if not self.ciphertext_blocks_var.get():
                messagebox.showwarning("Warning", "Please encrypt first or enter ciphertext blocks.")
                return
                
            # Parse ciphertext blocks
            ciphertext_blocks_hex = self.ciphertext_blocks_var.get().split(',')
            ciphertext_blocks = [int(block.strip(), 16) for block in ciphertext_blocks_hex]
            
            key = int(self.block_key_var.get(), 16)
            mode = self.mode_var.get()
            
            # Capture log output
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                if mode == "ECB":
                    plaintext_blocks = self.mini_aes.decrypt_ecb(ciphertext_blocks, key)
                else:  # CBC mode
                    iv = int(self.iv_var.get(), 16)
                    plaintext_blocks = self.mini_aes.decrypt_cbc(ciphertext_blocks, key, iv)
            
            log_output = f.getvalue()
            
            # Format plaintext blocks for display
            plaintext_blocks_hex = [f"{block:04X}" for block in plaintext_blocks]
            self.plaintext_blocks_var.set(','.join(plaintext_blocks_hex))
            
            # Update log display
            self.block_log.delete(1.0, tk.END)
            self.block_log.insert(tk.END, log_output)
            
            # Auto-scroll to the bottom
            self.block_log.see(tk.END)
            
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {str(e)}")
    
    def save_block_mode_results(self):
        """Save the block mode encryption results to a file."""
        try:
            if not self.ciphertext_blocks_var.get():
                messagebox.showwarning("Warning", "Please encrypt first.")
                return
                
            # Parse plaintext and ciphertext blocks
            plaintext_blocks_hex = self.plaintext_blocks_var.get().split(',')
            plaintext_blocks = [int(block.strip(), 16) for block in plaintext_blocks_hex]
            
            ciphertext_blocks_hex = self.ciphertext_blocks_var.get().split(',')
            ciphertext_blocks = [int(block.strip(), 16) for block in ciphertext_blocks_hex]
            
            key = int(self.block_key_var.get(), 16)
            
            # Ask user for file location and format
            file_types = [('Text files', '*.txt'), ('CSV files', '*.csv'), ('All files', '*.*')]
            file_path = filedialog.asksaveasfilename(filetypes=file_types, defaultextension=".txt")
            
            if file_path:
                if file_path.endswith('.csv'):
                    self.mini_aes.save_encryption_data(file_path, plaintext_blocks, key, ciphertext_blocks, mode="csv")
                else:
                    self.mini_aes.save_encryption_data(file_path, plaintext_blocks, key, ciphertext_blocks, mode="txt")
                
                messagebox.showinfo("Success", f"Results saved to {file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error saving results: {str(e)}")
    
    def clear_block_mode(self):
        """Clear the block mode tab inputs and outputs."""
        self.plaintext_blocks_var.set("ABCD,1234,5678,90EF")
        self.block_key_var.set("DEAD")
        self.ciphertext_blocks_var.set("")
        self.iv_var.set("1111")
        self.block_log.delete(1.0, tk.END)
    
    # ========== File Operations Tab Functions ==========
    
    def browse_load_file(self):
        """Browse for a file to load using the file explorer."""
        file_types = [('Text files', '*.txt'), ('Binary files', '*.bin'), ('All files', '*.*')]
        file_path = filedialog.askopenfilename(
            title="Select file to process",
            filetypes=file_types
        )
        
        if file_path:
            self.load_file_path_var.set(file_path)
            
            # If file name contains "Encrypted", automatically set to decrypt mode
            # and ask for the encryption key
            if "Encrypted" in os.path.basename(file_path):
                self.file_op_var.set("decrypt")
                self.prompt_for_key()
    
    def prompt_for_key(self):
        """Prompt the user for the encryption key if decrypting a file with 'Encrypted' in the name."""
        key_dialog = tk.Toplevel(self.root)
        key_dialog.title("Enter Encryption Key")
        key_dialog.geometry("400x150")
        key_dialog.resizable(False, False)
        key_dialog.transient(self.root)
        key_dialog.grab_set()
        
        # Center the dialog on the screen
        key_dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + (self.root.winfo_width() / 2) - 200,
            self.root.winfo_rooty() + (self.root.winfo_height() / 2) - 75
        ))
        
        ttk.Label(key_dialog, text="This file was encrypted with Mini-AES.\nPlease enter the encryption key used:").pack(pady=10)
        
        key_var = tk.StringVar()
        key_entry = ttk.Entry(key_dialog, textvariable=key_var, width=30)
        key_entry.pack(pady=10)
        key_entry.focus_set()
        
        def set_key():
            self.file_key_var.set(key_var.get())
            key_dialog.destroy()
        
        ttk.Button(key_dialog, text="OK", command=set_key).pack(pady=10)
        
        # Handle Enter key press
        key_dialog.bind('<Return>', lambda event: set_key())
        
        # Wait for the dialog to be closed
        self.root.wait_window(key_dialog)
    
    def process_file(self):
        """Process (encrypt/decrypt) the selected file."""
        try:
            file_path = self.load_file_path_var.get()
            
            if not file_path:
                messagebox.showwarning("Warning", "Please select a file to process.")
                return
            
            # Get operation type and key
            operation = self.file_op_var.get()
            try:
                key = int(self.file_key_var.get(), 16)
            except ValueError:
                messagebox.showerror("Error", "Invalid key format. Please enter a hexadecimal value.")
                return
            
            # Get block mode
            block_mode = self.file_mode_var.get()
            
            # Read the file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Process content based on operation type
            self.file_data_display.delete(1.0, tk.END)
            self.file_data_display.insert(tk.END, f"=== Processing File: {os.path.basename(file_path)} ===\n")
            self.file_data_display.insert(tk.END, f"Operation: {'Encryption' if operation == 'encrypt' else 'Decryption'}\n")
            self.file_data_display.insert(tk.END, f"Block Mode: {block_mode}\n")
            self.file_data_display.insert(tk.END, f"Key: 0x{key:04X}\n\n")
            
            # Prepare output file name with _Encrypted or _Decrypted suffix
            file_dir = os.path.dirname(os.path.abspath(__file__))  # Directory where the code is located
            file_name = os.path.basename(file_path)
            file_base, file_ext = os.path.splitext(file_name)
            
            # Remove _Encrypted suffix if decrypting
            if operation == 'decrypt' and file_base.endswith('_Encrypted'):
                file_base = file_base[:-10]  # Remove "_Encrypted"
                
            # Add appropriate suffix for the operation
            if operation == 'encrypt':
                output_file_name = f"{file_base}_Encrypted{file_ext}"
            else:
                output_file_name = f"{file_base}_Decrypted{file_ext}"
                
            output_path = os.path.join(file_dir, output_file_name)
            
            # Convert file content to 16-bit blocks
            blocks = []
            for i in range(0, len(file_content), 2):
                if i + 1 < len(file_content):
                    block = (file_content[i] << 8) | file_content[i + 1]
                else:
                    # Pad the last block if needed
                    block = file_content[i] << 8
                blocks.append(block)
            
            self.file_data_display.insert(tk.END, f"File size: {len(file_content)} bytes\n")
            self.file_data_display.insert(tk.END, f"Number of blocks: {len(blocks)}\n\n")
            
            # Process blocks based on operation and block mode
            if operation == 'encrypt':
                if block_mode == 'ECB':
                    processed_blocks = self.mini_aes.encrypt_ecb(blocks, key)
                else:  # CBC mode
                    iv = int(self.file_iv_var.get(), 16)
                    processed_blocks = self.mini_aes.encrypt_cbc(blocks, key, iv)
            else:  # Decrypt
                if block_mode == 'ECB':
                    processed_blocks = self.mini_aes.decrypt_ecb(blocks, key)
                else:  # CBC mode
                    iv = int(self.file_iv_var.get(), 16)
                    processed_blocks = self.mini_aes.decrypt_cbc(blocks, key, iv)
            
            # Convert processed blocks back to bytes
            output_bytes = bytearray()
            for block in processed_blocks:
                output_bytes.append((block >> 8) & 0xFF)  # High byte
                output_bytes.append(block & 0xFF)         # Low byte
            
            # Write to output file
            with open(output_path, 'wb') as f:
                f.write(output_bytes)
            
            self.file_data_display.insert(tk.END, f"Processing completed successfully.\n")
            self.file_data_display.insert(tk.END, f"Output file saved as: {output_file_name}\n")
            self.file_data_display.insert(tk.END, f"Full path: {output_path}\n")
            
            messagebox.showinfo("Success", f"File processed successfully.\nSaved as: {output_file_name}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error processing file: {str(e)}")
            self.file_data_display.insert(tk.END, f"ERROR: {str(e)}\n")
        
        # Auto-scroll to the bottom
        self.file_data_display.see(tk.END)
    
    def save_log(self):
        """Save the current log to a file."""
        try:
            # Ask user for file location
            file_types = [('Text files', '*.txt'), ('All files', '*.*')]
            file_path = filedialog.asksaveasfilename(filetypes=file_types, defaultextension=".txt")
            
            if file_path:
                with open(file_path, 'w') as f:
                    # Get the current tab's log content
                    current_tab = self.notebook.index(self.notebook.select())
                    
                    if current_tab == 0:  # Single Block tab
                        log_content = self.single_log.get(1.0, tk.END)
                    elif current_tab == 1:  # Block Mode tab
                        log_content = self.block_log.get(1.0, tk.END)
                    elif current_tab == 2:  # File Operations tab
                        log_content = self.file_data_display.get(1.0, tk.END)
                    elif current_tab == 3:  # Avalanche tab
                        log_content = self.avalanche_results.get(1.0, tk.END)
                    
                    f.write(log_content)
                
                messagebox.showinfo("Success", f"Log saved to {file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error saving log: {str(e)}")
    
    # ========== Avalanche Tab Functions ==========
    
    def run_avalanche_test(self):
        """Run the avalanche effect test."""
        try:
            plaintext = int(self.av_plaintext_var.get(), 16)
            key = int(self.av_key_var.get(), 16)
            modify_plaintext = self.modify_var.get() == "plaintext"
            bit_position = int(self.bit_position_var.get())
            
            # Capture log output
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                original_cipher, modified_cipher, differing_bits = self.mini_aes.analyze_avalanche(
                    plaintext, key, modify_plaintext, bit_position
                )
            
            log_output = f.getvalue()
            
            # Update results display
            self.avalanche_results.delete(1.0, tk.END)
            self.avalanche_results.insert(tk.END, log_output)
            
            # Auto-scroll to the bottom
            self.avalanche_results.see(tk.END)
            
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {str(e)}")
    
    def save_avalanche_results(self):
        """Save the avalanche test results to a file."""
        try:
            if not self.avalanche_results.get(1.0, tk.END).strip():
                messagebox.showwarning("Warning", "Please run a test first.")
                return
            
            # Ask user for file location
            file_types = [('Text files', '*.txt'), ('All files', '*.*')]
            file_path = filedialog.asksaveasfilename(filetypes=file_types, defaultextension=".txt")
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(self.avalanche_results.get(1.0, tk.END))
                
                messagebox.showinfo("Success", f"Results saved to {file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error saving results: {str(e)}")


def main():
    """Main function to run the GUI."""
    root = tk.Tk()
    app = MiniAESGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()