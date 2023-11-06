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

# 混合列（此处省略混合列，因为S-AES中混合列比较复杂）

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
    # 混合列，此处省略
    state = add_round_key(state, ((keys[2] << 8) | keys[3]))
    
    # 第2轮加密
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, ((keys[4] << 8) | keys[5]))
    
    return state

# ASCII字符串转换为16位的数据
def ascii_to_16bit(ascii_str):
    if len(ascii_str) != 2:
        raise ValueError("String must be exactly 2 characters long.")
    return (ord(ascii_str[0]) << 8) | ord(ascii_str[1])

# 16位数据转换为ASCII字符串
def bit16_to_ascii(bit16):
    char1 = chr((bit16 & 0xFF00) >> 8)
    char2 = chr(bit16 & 0x00FF)
    return char1 + char2

# GUI部分
def encrypt():
    try:
        if input_type_var.get() == 'ascii':
            plaintext_str = plaintext_entry.get()
            plaintext = ascii_to_16bit(plaintext_str)
        else:
            plaintext = int(plaintext_entry.get(), 16)
        
        key_str = key_entry.get()
        key = ascii_to_16bit(key_str) if len(key_str) == 2 else int(key_str, 16)
        
        ciphertext = s_aes_encrypt(plaintext, key)
        
        if input_type_var.get() == 'ascii':
            # 将16位二进制转换为ASCII字符串
            ciphertext_str = bit16_to_ascii(ciphertext)
        else:
            ciphertext_str = f"{ciphertext:04X}"
        
        # 更新输出标签
        output_label.config(text=f"Ciphertext: {ciphertext_str}")
    except ValueError as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("S-AES Encryption")

# 输入类型选择
input_type_var = tk.StringVar(value='hex')
ascii_radio = tk.Radiobutton(root, text="ASCII input", variable=input_type_var, value='ascii')
hex_radio = tk.Radiobutton(root, text="Hex input", variable=input_type_var, value='hex')
ascii_radio.grid(row=0, column=0)
hex_radio.grid(row=0, column=1)

# 输入标签和输入框
tk.Label(root, text="Plaintext:").grid(row=1, column=0)
plaintext_entry = tk.Entry(root)
plaintext_entry.grid(row=1, column=1)

tk.Label(root, text="Key (2 char ASCII or 16 bit hex):").grid(row=2, column=0)
key_entry = tk.Entry(root)
key_entry.grid(row=2, column=1)

# 加密按钮
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=3, column=0, columnspan=2)

# 输出标签
output_label = tk.Label(root, text="Ciphertext will appear here")
output_label.grid(row=4, column=0, columnspan=2)

root.mainloop()
