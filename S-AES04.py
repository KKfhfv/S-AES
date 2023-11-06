import tkinter as tk
from tkinter import messagebox

# S-AES的一些参数和S盒
s_box = {
    0x00: 0x09, 0x01: 0x04, 0x02: 0x0A, 0x03: 0x0B,
    0x04: 0x0D, 0x05: 0x01, 0x06: 0x08, 0x07: 0x05,
    0x08: 0x06, 0x09: 0x02, 0x0A: 0x00, 0x0B: 0x03,
    0x0C: 0x0C, 0x0D: 0x0E, 0x0E: 0x0F, 0x0F: 0x07,
}
# 用于密钥生成的S盒
w_box = {
    0x00: 0x08, 0x01: 0x01, 0x02: 0x02, 0x03: 0x0B,
    0x04: 0x04, 0x05: 0x0D, 0x06: 0x06, 0x07: 0x05,
    0x08: 0x0A, 0x09: 0x09, 0x0A: 0x0C, 0x0B: 0x03,
    0x0C: 0x0F, 0x0D: 0x0E, 0x0E: 0x07, 0x0F: 0x00,
}
# 轮常量
rc = [0x00, 0x80, 0x30]
# 按位异或
def bitwise_xor(a, b):
    return a ^ b
# 密钥扩展
def key_expansion(key):
    w = [None] * 6
    w[0] = (key & 0xFF00) >> 8
    w[1] = key & 0x00FF
    
    for i in range(2, 6):
        temp = w[i - 1]
        if i % 2 == 0:
            # 旋转
            temp = ((temp & 0x0F) << 4) | ((temp & 0xF0) >> 4)
            # S盒替换
            temp = (w_box[(temp & 0xF0) >> 4] << 4) | w_box[temp & 0x0F]
            # 轮常量
            temp = bitwise_xor(temp, rc[i // 2])
        w[i] = bitwise_xor(w[i - 2], temp)
    
    return w
# 字节代换
def sub_bytes(state):
    return (s_box[(state & 0xF0) >> 4] << 4) | s_box[state & 0x0F]
# 行移位
def shift_rows(state):
    return ((state & 0xF0) >> 4) | ((state & 0x0F) << 4)
# 轮密钥加
def add_round_key(state, key):
    return bitwise_xor(state, key)

# S-AES 加密过程
def s_aes_encrypt(plaintext, key):
    keys = key_expansion(key)
    # 初始轮密钥加
    state = add_round_key(plaintext, ((keys[0] << 8) | keys[1]))
    # 第1轮加密
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, ((keys[2] << 8) | keys[3]))
    # 第2轮加密
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, ((keys[4] << 8) | keys[5]))
    
    return state
# 逆S盒
inv_s_box = {v: k for k, v in s_box.items()}

# 逆行移位
def inv_shift_rows(state):
    return ((state & 0x0F) << 4) | ((state & 0xF0) >> 4)
# 逆字节代换
def inv_sub_bytes(state):
    return (inv_s_box[(state & 0xF0) >> 4] << 4) | inv_s_box[state & 0x0F]
# S-AES 解密过程
def s_aes_decrypt(ciphertext, key):
    keys = key_expansion(key)
    # 初始轮密钥加
    state = add_round_key(ciphertext, ((keys[4] << 8) | keys[5]))
    # 第1轮解密
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, ((keys[2] << 8) | keys[3]))
    # 第2轮解密
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, ((keys[0] << 8) | keys[1])) 
    return state


# S-AES三重加密
def triple_s_aes_encrypt(plaintext, keys):
    k1, k2, k3 = keys
    # 第一次使用K1加密
    encrypted = s_aes_encrypt(plaintext, k1)
    # 第二次使用K2解密（注意：这里用的还是加密函数，因为S-AES的解密和加密是相同的过程）
    decrypted = s_aes_encrypt(encrypted, k2)
    # 第三次使用K3加密
    encrypted_again = s_aes_encrypt(decrypted, k3)
    return encrypted_again

# S-AES三重解密
def triple_s_aes_decrypt(ciphertext, keys):
    k1, k2, k3 = keys
    # 第一次使用K3解密
    decrypted = s_aes_encrypt(ciphertext, k3)
    # 第二次使用K2加密
    encrypted = s_aes_encrypt(decrypted, k2)
    # 第三次使用K1解密
    decrypted_again = s_aes_encrypt(encrypted, k1)
    return decrypted_again

# 以下是GUI部分的代码，其中包含了用户交互和密钥输入
# 注意：用户需要输入一个48位的十六进制密钥，我们将其分割为三个16位的密钥
# GUI部分
def perform_action():
    try:
        # 获取输入值
        plaintext = int(plaintext_entry.get(), 16)
        key_input = key_entry.get()
        
        # 验证密钥长度
        if len(key_input) != 12:  # 12个16进制数字对应48位
            messagebox.showerror("Error", "Key must be 48 bits long.")
            return
        
        key = int(key_input, 16)
        
        # 将48位密钥分为三个16位的密钥
        key1 = (key >> 32) & 0xFFFF
        key2 = (key >> 16) & 0xFFFF
        key3 = key & 0xFFFF
        keys = (key1, key2, key3)
        
        if operation.get() == 'Encrypt':
            result = triple_s_aes_encrypt(plaintext, keys)
        else:
            result = triple_s_aes_decrypt(plaintext, keys)
        
        # 显示结果
        result_var.set(f"Result (16 bit binary): {result:016b}")
    except ValueError:
        messagebox.showerror("Error", "Invalid input, please enter hexadecimal values.")

root = tk.Tk()
root.title("Triple S-AES Encryption/Decryption")

# 输入标签和输入框
tk.Label(root, text="Plaintext (16 bit hex):").grid(row=0, column=0)
plaintext_entry = tk.Entry(root)
plaintext_entry.grid(row=0, column=1)

tk.Label(root, text="Key (48 bit hex):").grid(row=1, column=0)
key_entry = tk.Entry(root)
key_entry.grid(row=1, column=1)

# 加密和解密操作的单选按钮
operation = tk.StringVar(value="Encrypt")
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=operation, value="Encrypt")
decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=operation, value="Decrypt")
encrypt_radio.grid(row=2, column=0)
decrypt_radio.grid(row=2, column=1)

# 执行按钮
action_button = tk.Button(root, text="Perform Action", command=perform_action)
action_button.grid(row=3, column=0, columnspan=2)

# 结果显示
result_var = tk.StringVar()
tk.Label(root, textvariable=result_var).grid(row=4, column=0, columnspan=2)

root.mainloop()