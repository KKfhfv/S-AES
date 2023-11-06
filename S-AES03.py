def generate_possible_keys():
    for key in range(0x10000):  # 16位密钥空间，从0到0xFFFF
        yield key

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

# 已知的明文和密文对
known_plaintext = 0x1234
known_ciphertext = 0xb926

# 第一步：使用所有可能的密钥对明文进行加密
# 并存储中间状态和对应的密钥
encryption_table = {}
for key1 in generate_possible_keys():
    intermediate = s_aes_encrypt(known_plaintext, key1)
    encryption_table[intermediate] = key1

# 第二步：使用所有可能的密钥对密文进行解密
# 并查找中间状态是否在加密表中
for key2 in generate_possible_keys():
    intermediate = s_aes_decrypt(known_ciphertext, key2)
    if intermediate in encryption_table:
        found_key1 = encryption_table[intermediate]
        found_key2 = key2
        print(f"Found matching keys: K1 = {found_key1:04X}, K2 = {found_key2:04X}")
        # 生成32位密钥
        found_key = (found_key1 << 16) | found_key2
        print(f"Combined 32-bit key: {found_key:08X}")
        break
else:
    print("No matching keys found.")
