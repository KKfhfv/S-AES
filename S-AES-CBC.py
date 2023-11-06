
import tkinter as tk
from tkinter import messagebox
import random
import os
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

# 使用S-AES加密块的函数
def s_aes_cbc_encrypt_block(block, key, iv):
    # 在CBC模式中，先与IV进行XOR，然后加密
    block = block ^ iv
    return s_aes_encrypt(block, key)

# 使用S-AES解密块的函数
def s_aes_cbc_decrypt_block(block, key, iv):
    # 解密后与IV进行XOR
    decrypted = s_aes_encrypt(block, key)
    return decrypted ^ iv

# 使用S-AES进行CBC模式加密的函数
def s_aes_cbc_encrypt(message, key, iv):
    # 消息需要按16位分块
    blocks = [message[i:i+16] for i in range(0, len(message), 16)]
    encrypted_blocks = []
    previous_block = iv
    for block in blocks:
        # 加密每个块
        block = int(block, 2)  # 将块从二进制字符串转换为整数
        encrypted_block = s_aes_cbc_encrypt_block(block, key, previous_block)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block  # 更新IV为当前加密块
    return encrypted_blocks

# 使用S-AES进行CBC模式解密的函数
def s_aes_cbc_decrypt(ciphertext_blocks, key, iv):
    decrypted_blocks = []
    previous_block = iv
    for block in ciphertext_blocks:
        decrypted_block = s_aes_cbc_decrypt_block(block, key, previous_block)
        decrypted_blocks.append(f"{decrypted_block:016b}")  # 二进制格式化
        previous_block = block  # 更新IV为当前密文块
    return ''.join(decrypted_blocks)

def generate_iv():
    # 返回一个16位的随机数，这里用的是Python标准库中的os.urandom来生成安全的随机数
    return int.from_bytes(os.urandom(2), 'big')  # 从2字节的随机数据中生成一个整数

# GUI相关函数
def perform_action():
    try:
        # 获取输入值
        message = plaintext_entry.get()
        key_input = key_entry.get()
        
        # 验证密钥长度
        if len(key_input) != 8:  # 8个16进制数字对应32位
            messagebox.showerror("Error", "Key must be 32 bits long.")
            return
        
        key = int(key_input, 16)
        iv = generate_iv()  # 生成随机IV
        iv_var.set(f"{iv:04x}".upper())  # 显示IV
        
        if operation.get() == 'Encrypt':
            # 将明文消息转换为二进制
            message_binary = ''.join(f"{int(char, 16):04b}" for char in message)
            encrypted_blocks = s_aes_cbc_encrypt(message_binary, key, iv)
            result = ' '.join(f"{block:016b}" for block in encrypted_blocks)
        else:
            # 将密文消息从二进制字符串转换为整数块列表
            ciphertext_blocks = [int(block, 2) for block in message.split()]
            result = s_aes_cbc_decrypt(ciphertext_blocks, key, iv)
        
        result_var.set(f"Result: {result}")
    except ValueError:
        messagebox.showerror("Error", "Invalid input, please enter hexadecimal values.")


# GUI布局
root = tk.Tk()
root.title("S-AES CBC Encryption/Decryption")

# 输入标签和输入框
tk.Label(root, text="Message (hex):").grid(row=0, column=0)
plaintext_entry = tk.Entry(root, width=50)
plaintext_entry.grid(row=0, column=1)

tk.Label(root, text="Key (32 bit hex):").grid(row=1, column=0)
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

# IV显示
iv_var = tk.StringVar()
tk.Label(root, text="IV (16 bit hex):").grid(row=4, column=0)
tk.Label(root, textvariable=iv_var).grid(row=4, column=1)

# 结果显示
result_var = tk.StringVar()
tk.Label(root, text="Result:").grid(row=5, column=0)
tk.Label(root, textvariable=result_var, width=50, wraplength=400).grid(row=5, column=1)

# 启动GUI主循环
root.mainloop()