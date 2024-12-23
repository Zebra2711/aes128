"""
    NHÓM 1.THUẬT TOÁN MÃ HÓA AES-128

    AES 128 bit Cipher Block Chaining (CBC) Mode and Electronic Codebook (ECB) Mode
    Password-Based Key Derivation Function 2(PBKDF2),
    Cryptographic Message Syntax PKCS #7,
    Hash-based message authentication codes (HMAC) SHA256
    Encrypt Input   :   Plain Text type UTF-8
            Output  :   Cipher Text type BASE64
    Encrypt Input   :   Cipher Text type BASE64
            Output  :   Plain Text type UTF-8
    KEY type UTF-8


"""
MODE_ECB = 1
MODE_CBC = 2
AES_KEY_SIZE_DEFAULT = 16
HMAC_KEY_SIZE = 16
IV_SIZE = 16
SALT_SIZE = 16
HMAC_SIZE = 32
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes_to_matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix_to_bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.

    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes_to_matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes_to_matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix_to_bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes_to_matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix_to_bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))

    def encrypt_ecb(self, plaintext):
        plaintext = pad(plaintext)
        blocks = []
        for plaintext_block in split_blocks(plaintext):
            block = self.encrypt_block(plaintext_block)
            blocks.append(block)
        return b''.join(blocks)

    def decrypt_ecb(self, ciphertext):
        blocks = []
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(self.decrypt_block(ciphertext_block))
        return unpad(b''.join(blocks))



# def get_key_iv(password, salt, workload=100000):
#     """
#     Stretches the password and extracts an AES key, an HMAC key and an AES
#     initialization vector.
#     """
#     from hashlib import pbkdf2_hmac
#     stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE)
#     aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
#     hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
#     iv = stretched[:IV_SIZE]
#     print(f"PBKDF2 ==> aes_key:{aes_key}, hmac_key:{hmac_key}, iv:{iv}")
#     return aes_key, hmac_key, iv

def get_key_iv_argon2(passwd, salt, key_size=AES_KEY_SIZE_DEFAULT):
    """
    Stretches the password and extracts an AES key, an HMAC key and an AES
    initialization vector.
    """
    from pyargon2 import hash_bytes
    AES_KEY_SIZE = key_size
    print(AES_KEY_SIZE)
    stretched = hash_bytes(passwd,salt,encoding='raw',hash_len=AES_KEY_SIZE+HMAC_KEY_SIZE+IV_SIZE)
    aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    print(f"ARGON2 ==> aes_key:{aes_key}, hmac_key:{hmac_key}, iv:{iv}")
    return aes_key, hmac_key, iv


def encrypt(key, plaintext, mode=MODE_ECB, key_size=AES_KEY_SIZE_DEFAULT):
    from base64 import b64encode
    from hmac import new as new_hmac
    from os import urandom
    print("\nAES128 ENCRYPT",end='\t')
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    """
        Encrypts `plaintext` with `key` using AES-128, an HMAC to verify integrity,
        and PBKDF2 to stretch the given key.

        The exact algorithm is specified in the module docstring.
    """
    salt = urandom(SALT_SIZE)
    print(f"SALT: {salt}")
    #key, hmac_key, iv = get_key_iv(key, salt, workload)
    key, hmac_key, iv = get_key_iv_argon2(key, salt, key_size)
    print(f"KEY_LEN:{len(key)}")

    if mode == MODE_ECB:
        print("(ECB MODE)")
        # Convert ciphertext from bytes to base64
        ciphertext = AES(key).encrypt_ecb(plaintext)
    elif mode == MODE_CBC:
        print("(CBC MODE)")
        ciphertext = AES(key).encrypt_cbc(plaintext, iv)
    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE

    # Convert ciphertext from bytes to base64
    ciphertext_base64 = b64encode(hmac + salt + ciphertext).decode()

    return ciphertext_base64



def decrypt(key, ciphertext_base64, mode=MODE_ECB, key_size=AES_KEY_SIZE_DEFAULT):
    """
        Decrypts `ciphertext` with `key` using AES-128, an HMAC to verify integrity,
        and PBKDF2 to stretch the given key.

        The exact algorithm is specified in the module docstring.
    """
    from hmac import new as new_hmac, compare_digest
    from base64 import b64decode
    ciphertext =b64decode(ciphertext_base64.encode())
    print("\nAES128 DECRYPT",end='\t')
    #print(f'check:{ciphertext}')
    assert len(ciphertext) % 16 == 0, "Ciphertext must be made of full 16-byte blocks."

    assert len(ciphertext) >= 32, """
        Ciphertext must be at least 32 bytes long (16 byte salt + 16 byte block). To
        encrypt or decrypt single blocks use `AES(key).decrypt_block(ciphertext)`.
        """
    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    #key, hmac_key, iv = get_key_iv(key, salt, workload)
    key, hmac_key, iv = get_key_iv_argon2(key, salt,key_size)

    if mode == MODE_ECB:
        print("(ECB MODE)")
        plaintext = AES(key).decrypt_ecb(ciphertext)

        # return to plaintext utf-8 encoded
        return plaintext.decode('utf-8')
    elif mode == MODE_CBC:
        print("(CBC MODE)")
        expected_hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
        assert compare_digest(hmac, expected_hmac), 'Ciphertext corrupted or tampered.'

        # return to plaintext utf-8 encoded
        return AES(key).decrypt_cbc(ciphertext, iv).decode('utf-8')

# def base64_to_hex(text_base64):
#     return b64encode(text_base64.encode()).hex()


"""
    Encrypt:
        base64      encrypt(Key, PlainText, Mode)
    Decrypt:
        utf-8       decrypt(Key, PlainText, Mode)
    "Variable": @Key         utf-8
                @PlainText   utf-8
                @Mode        MODE_ECB = 1, MODE_CBC = 2

"""

import customtkinter as ctk
class MyApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES")
        self.geometry("420x600")
        self.resizable(False, False)

        # self.iconbitmap(os.path.dirname(os.path.abspath(__file__))+"/aes.ico")

        # Create a select box (dropdown)
        self.select_var = ctk.StringVar()
        self.select_var.set("Encrypt")  # Default selection
        self.select_box = ctk.CTkComboBox(self,width=90, values=["Encrypt", "Decrypt"], variable=self.select_var,state="readonly",command=self.update_label_text)
        self.select_box.grid(row=0, column=0, padx=10, pady=5,sticky="W")

        self.select_mode = ctk.StringVar()
        self.select_mode.set("ECB")  # Default selection
        self.select_mode = ctk.CTkComboBox(self, width=70,values=["ECB", "CBC"], variable=self.select_mode,state="readonly")
        self.select_mode.grid(row=0, column=2, padx=10, pady=5)

        self.key_lenght = ctk.StringVar()
        self.key_lenght.set("128")  # Default selection
        self.key_lenght = ctk.CTkComboBox(self, width=70,values=["128","196","256"], variable=self.key_lenght,state="readonly")
        self.key_lenght.grid(row=0, column=3, padx=10, pady=5)

        # Create the button
        self.go_button = ctk.CTkButton(self,width=80, text="Go", command=self.on_go_button_click)
        self.go_button.grid(row=0, column=4, padx=10, pady=5,sticky="E")


        # Create input text boxes
        self.label_input = ctk.CTkLabel(self, text="Plain Text",fg_color="transparent")
        self.label_input.grid(row=1, column=0,columnspan=5, padx=10, pady=0, sticky="W")


        self.textbox_input= ctk.CTkTextbox(self,width = 400)
        self.textbox_input.grid(row=2, column=0, columnspan=5,padx=10, pady=5)



        # KEY
        self.label_key = ctk.CTkLabel(self, text="Key", fg_color="transparent")
        self.label_key.grid(row=3, column=0,columnspan=5, padx=10, pady=0, sticky="W")
        self.textbox_key= ctk.CTkEntry(self,width = 400, placeholder_text="Enter the key...")
        self.textbox_key.grid(row=4, column=0,columnspan=5, padx=10, pady=5)

        #OUTPUT
        self.label_output = ctk.CTkLabel(self, text="Cipher Text", fg_color="transparent")
        self.label_output.grid(row=5, column=0,columnspan=5, padx=10, pady=0, sticky="W")
        self.textbox_output = ctk.CTkTextbox(self,width = 400,state="disabled")
        self.textbox_output.grid(row=6, column=0,columnspan=5, padx=10, pady=5)

    def update_label_text(self,event):
        mode = self.select_var.get()
        if mode == "Encrypt":
            self.label_input.configure(text="Plain Text")
            self.label_output.configure(text="Cipher Text")
        else:
            self.label_input.configure(text="Cipher Text")
            self.label_output.configure(text="Plain Text")
            self.textbox_input.delete("0.0", "end")
            self.textbox_input.insert("0.0",self.textbox_output.get("0.0", "end"))
            self.textbox_output.configure(state="normal")
            self.textbox_output.delete("0.0", "end")
            self.textbox_output.configure(state="disabled")

    def on_go_button_click(self):
        from numpy import fromstring
        mode = self.select_var.get()
        mode_t = 1
        if self.select_mode.get() == "CBC":
            mode_t = 2
        self.textbox_output.configure(state="normal")
        self.textbox_output.delete("0.0", "end")

        Key = self.textbox_key.get()
        Input = self.textbox_input.get("0.0","end")
        bit = fromstring(self.key_lenght.get(),dtype=int,sep=' ')[0]
        print(bit)
        key_size = 16
        if bit == 196:
            key_size = 24
        elif bit == 256:
            key_size = 32

        try:
            if mode == "Encrypt":
                Output = encrypt(Key, Input,mode_t,key_size)
            else:
                Output = decrypt(Key, Input,mode_t,key_size)
        except Exception as ERROR:
            Output = f"""An error occurred {ERROR}\n
                        Check Input, Key or Mode again...
                    """

        #print(Output)
        self.textbox_output.insert("0.0",Output)
        self.textbox_output.configure(state="disabled")

if __name__ == "__main__":
    app = MyApp()
    app.mainloop()
