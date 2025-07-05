import hashlib
import numpy as np
from PIL import Image, ImageTk, PngImagePlugin
import hmac
import os
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox


# =========================
# DNA OPERATIONS
# =========================

DNA_TABLE = {
    0: {'00': 'A', '01': 'C', '10': 'G', '11': 'T'},
    1: {'00': 'A', '01': 'G', '10': 'C', '11': 'T'},
    2: {'00': 'C', '01': 'A', '10': 'T', '11': 'G'},
    3: {'00': 'C', '01': 'T', '10': 'A', '11': 'G'},
    4: {'00': 'G', '01': 'A', '10': 'T', '11': 'C'},
    5: {'00': 'G', '01': 'T', '10': 'A', '11': 'C'},
    6: {'00': 'T', '01': 'C', '10': 'G', '11': 'A'},
    7: {'00': 'T', '01': 'G', '10': 'C', '11': 'A'}
}

DNA_ADD = {
    'A': {'A': 'A', 'C': 'C', 'G': 'G', 'T': 'T'},
    'C': {'A': 'C', 'C': 'G', 'G': 'T', 'T': 'A'},
    'G': {'A': 'G', 'C': 'T', 'G': 'A', 'T': 'C'},
    'T': {'A': 'T', 'C': 'A', 'G': 'C', 'T': 'G'}
}

DNA_XOR = {
    'A': {'A': 'A', 'C': 'C', 'G': 'G', 'T': 'T'},
    'C': {'A': 'C', 'C': 'A', 'G': 'T', 'T': 'G'},
    'G': {'A': 'G', 'C': 'T', 'G': 'A', 'T': 'C'},
    'T': {'A': 'T', 'C': 'G', 'G': 'C', 'T': 'A'}
}


# =========================
# Encryption Class
# =========================

class ImageEncryptor:
    rounds = 3

    @staticmethod
    def pbkdf2_key(password, salt, length=32):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000, dklen=length)

    @staticmethod
    def hybrid_chaotic_map(x, p, iterations):
        r = 3.99
        sequence = []
        for _ in range(iterations):
            if x < p:
                x = x / p
            else:
                x = (1 - x) / (1 - p)
            x = r * x * (1 - x)
            x = x % 1
            sequence.append(x)
        return sequence

    @staticmethod
    def dna_encode(bit_array, rule_sequence):
        if len(bit_array) % 2 != 0:
            bit_array += '0'
        required_rules = len(bit_array) // 2
        rule_sequence = (rule_sequence * (required_rules // len(rule_sequence) + 1))[:required_rules]
        dna_sequence = []
        for i in range(0, len(bit_array), 2):
            bits = bit_array[i:i + 2]
            rule = rule_sequence[i // 2] % 8
            dna_sequence.append(DNA_TABLE[rule][bits])
        return dna_sequence

    @staticmethod
    def dna_decode(dna_sequence, rule_sequence):
        bit_array = []
        for i, dna in enumerate(dna_sequence):
            rule = rule_sequence[i] % 8
            for bits, symbol in DNA_TABLE[rule].items():
                if symbol == dna:
                    bit_array.append(bits)
                    break
        return ''.join(bit_array)

    @staticmethod
    def permutation_diffusion(dna_seq, key, rule_seq, encrypting=True):
        len_seq = len(dna_seq)
        h1, h2 = int(key[:16].hex(), 16), int(key[16:32].hex(), 16)
        x1, p = (h1 / 1e15) % 1, (h2 / 1e15) % 1

        x_sequence = ImageEncryptor.hybrid_chaotic_map(x1, p, len_seq)
        y_sequence = [int(x * 1e15) % 256 for x in x_sequence]
        s_key = ImageEncryptor.dna_encode(''.join([format(y, '08b') for y in y_sequence]), rule_seq)

        d = dna_seq.copy()

        for _ in range(ImageEncryptor.rounds):
            temp = []
            if encrypting:
                temp.append(DNA_XOR[DNA_ADD[d[0]][s_key[0]]][s_key[0]])
                for i in range(1, len_seq):
                    if i % 2 == 1:
                        d_val = DNA_XOR[d[i]][s_key[i]]
                        d_val = DNA_XOR[d_val][temp[i - 1]]
                    else:
                        d_val = DNA_ADD[d[i]][s_key[i]]
                        d_val = DNA_XOR[d_val][temp[i - 1]]
                    temp.append(d_val)
                d = temp.copy()
            else:
                temp = [None] * len_seq
                for i in range(len_seq - 1, 0, -1):
                    if i % 2 == 1:
                        d_val = DNA_XOR[d[i]][s_key[i]]
                        d_val = DNA_XOR[d_val][d[i - 1]]
                    else:
                        d_val = DNA_ADD[d[i]][s_key[i]]
                        d_val = DNA_XOR[d_val][d[i - 1]]
                    temp[i] = d_val
                temp[0] = DNA_XOR[DNA_ADD[d[0]][s_key[0]]][s_key[0]]
                d = temp.copy()

        return d

    @staticmethod
    def generate_rule_sequence(key, length):
        h1, h2 = int(key[:16].hex(), 16), int(key[16:32].hex(), 16)
        x1, p = (h1 / 1e15) % 1, (h2 / 1e15) % 1
        x_sequence = ImageEncryptor.hybrid_chaotic_map(x1, p, length // 2 + 1)
        return [int(x * 1e15) % 8 for x in x_sequence]

    @staticmethod
    def generate_permutation_indexes(key, length):
        h1, h2 = int(key[:16].hex(), 16), int(key[16:32].hex(), 16)
        x1, p = (h1 / 1e15) % 1, (h2 / 1e15) % 1
        chaotic_seq = ImageEncryptor.hybrid_chaotic_map(x1, p, length)
        sorted_idx = np.argsort(chaotic_seq)
        return sorted_idx, np.argsort(sorted_idx)

    @staticmethod
    def compute_hmac(key, file_bytes):
        return hmac.new(key, file_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def encrypt_pixels(pixels, key):
        perm, inv_perm = ImageEncryptor.generate_permutation_indexes(key, len(pixels))
        pixels_perm = np.array(pixels)[perm]

        bit_array = ''.join([format(pixel, '08b') for pixel in pixels_perm])
        rule_seq = ImageEncryptor.generate_rule_sequence(key, len(bit_array))
        s1 = ImageEncryptor.dna_encode(bit_array, rule_seq)
        s2 = ImageEncryptor.permutation_diffusion(s1, key, rule_seq, encrypting=True)
        cipher_bits = ImageEncryptor.dna_decode(s2, rule_seq)[:len(bit_array)]
        cipher_pixels = [int(cipher_bits[i:i + 8], 2) for i in range(0, len(cipher_bits), 8)]

        return np.array(cipher_pixels)[inv_perm].tolist()

    @staticmethod
    def decrypt_pixels(pixels, key):
        perm, inv_perm = ImageEncryptor.generate_permutation_indexes(key, len(pixels))
        pixels_perm = np.array(pixels)[perm]

        bit_array = ''.join([format(pixel, '08b') for pixel in pixels_perm])
        rule_seq = ImageEncryptor.generate_rule_sequence(key, len(bit_array))
        sr1 = ImageEncryptor.dna_encode(bit_array, rule_seq)
        sr2 = ImageEncryptor.permutation_diffusion(sr1, key, rule_seq, encrypting=False)
        plain_bits = ImageEncryptor.dna_decode(sr2, rule_seq)
        plain_pixels = [int(plain_bits[i:i + 8], 2) for i in range(0, len(plain_bits), 8)]

        return np.array(plain_pixels)[inv_perm].tolist()

    @staticmethod
    def process_color_image(image, password, salt, encrypt=True):
        img_array = np.array(image)
        processed_channels = []

        for channel in range(3):
            channel_key = ImageEncryptor.pbkdf2_key(f"{password}_{channel}", salt)
            channel_pixels = img_array[:, :, channel].flatten().tolist()
            processed = ImageEncryptor.encrypt_pixels(channel_pixels, channel_key) if encrypt else ImageEncryptor.decrypt_pixels(channel_pixels, channel_key)
            processed_channel = np.array(processed).reshape(img_array.shape[0], img_array.shape[1])
            processed_channels.append(processed_channel)

        processed_array = np.stack(processed_channels, axis=-1)
        return Image.fromarray(np.clip(processed_array, 0, 255).astype('uint8'))


# =========================
# GUI
# =========================

class ImageEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool with DNA, Chaos & HMAC")
        self.root.geometry("900x600")

        Label(root, text="Enter Key:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.key_entry = Entry(root, width=40)
        self.key_entry.grid(row=0, column=1, padx=10, pady=10)

        Button(root, text="Select Image", command=self.select_image).grid(row=1, column=0, columnspan=2, sticky="ew", padx=10)
        Button(root, text="Encrypt Image", command=self.encrypt_image).grid(row=2, column=0, sticky="ew", padx=10)
        Button(root, text="Decrypt Image", command=self.decrypt_image).grid(row=2, column=1, sticky="ew", padx=10)
        Button(root, text="Save Processed Image", command=self.save_image).grid(row=3, column=0, columnspan=2, sticky="ew", padx=10)

        self.original_image_label = Label(root)
        self.original_image_label.grid(row=4, column=0, padx=10, pady=10)
        self.processed_image_label = Label(root)
        self.processed_image_label.grid(row=4, column=1, padx=10, pady=10)

        self.result_label = Label(root, text="", fg="blue")
        self.result_label.grid(row=5, column=0, columnspan=2)

        self.image = None
        self.processed_image = None
        self.last_hmac = None
        self.last_salt = None

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if path:
            self.image = Image.open(path).convert("RGB")
            self.image.thumbnail((300, 300))
            self.original_image_tk = ImageTk.PhotoImage(self.image)
            self.original_image_label.config(image=self.original_image_tk)
            self.last_hmac = self.image.info.get("hmac")
            salt_hex = self.image.info.get("salt")
            if salt_hex:
                self.last_salt = bytes.fromhex(salt_hex)
            else:
                self.last_salt = os.urandom(16)

    def encrypt_image(self):
        key = self.key_entry.get()
        if not self.image or not key:
            messagebox.showerror("Error", "Select image and enter key!")
            return
        self.last_salt = os.urandom(16)
        self.processed_image = ImageEncryptor.process_color_image(self.image, key, self.last_salt, encrypt=True)
        self.processed_image_tk = ImageTk.PhotoImage(self.processed_image)
        self.processed_image_label.config(image=self.processed_image_tk)

        full_bytes = np.array(self.processed_image).tobytes()
        self.last_hmac = ImageEncryptor.compute_hmac(key.encode(), full_bytes)

        self.result_label.config(text="Encryption complete.")

    def decrypt_image(self):
        key = self.key_entry.get()
        if not self.image or not key:
            messagebox.showerror("Error", "Select encrypted image and enter key!")
            return
        full_bytes = np.array(self.image).tobytes()
        test_hmac = ImageEncryptor.compute_hmac(key.encode(), full_bytes)
        if self.last_hmac and self.last_hmac != test_hmac:
            messagebox.showerror("Error", "Wrong key or corrupted image! HMAC mismatch.")
            return
        self.processed_image = ImageEncryptor.process_color_image(self.image, key, self.last_salt, encrypt=False)
        self.processed_image_tk = ImageTk.PhotoImage(self.processed_image)
        self.processed_image_label.config(image=self.processed_image_tk)
        self.result_label.config(text="Decryption complete.")

    def save_image(self):
        if not self.processed_image:
            messagebox.showerror("Error", "No processed image to save!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
        if path:
            try:
                meta = PngImagePlugin.PngInfo()
                if self.last_hmac:
                    meta.add_text("hmac", self.last_hmac)
                if self.last_salt:
                    meta.add_text("salt", self.last_salt.hex())
                self.processed_image.save(path, pnginfo=meta)
                messagebox.showinfo("Saved", "Image saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {e}")


# =========================
# Run App
# =========================

if __name__ == "__main__":
    root = Tk()
    app = ImageEncryptionApp(root)
    root.mainloop()
