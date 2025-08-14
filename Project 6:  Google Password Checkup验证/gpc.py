from phe import paillier
import hashlib
import random

# 服务器端
class Server:
    def __init__(self, leaked_passwords, public_key):
        # 把泄露密码转换成 SHA-1 哈希的整数
        self.public_key = public_key
        self.leaked_hashes = [int(hashlib.sha1(p.encode()).hexdigest(),16) for p in leaked_passwords]

    # 接收客户端加密的前缀，在加密状态下检查是否匹配泄露密码，返回加密结果列表
    def homomorphic_check(self, enc_prefixes):
        results = []
        for enc_prefix in enc_prefixes:
            match_found = 0
            for h in self.leaked_hashes:
                # 比较高 20 位前缀是否相同
                if (h >> (160-20)) == enc_prefix:
                    match_found = 1
                    break
            # 返回加密结果
            enc_result = self.public_key.encrypt(match_found)
            results.append(enc_result)
        return results

# 客户端
class Client:
    def __init__(self, server):
        # 生成 Paillier 公私钥
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        self.server = server

    # 把密码 SHA-1 哈希成整数
    def hash_password(self, password):
        return int(hashlib.sha1(password.encode()).hexdigest(),16)

    # 取哈希的高 prefix_bits 位作为前缀
    def get_prefix(self, h, prefix_bits=20):
        return h >> (160 - prefix_bits)

    # 检查密码是否泄露
    def check_password(self, password):
        h = self.hash_password(password)
        prefix = self.get_prefix(h)
        # 加密前缀并发送给服务器
        enc_prefix = self.public_key.encrypt(prefix)
        # 服务器返回加密结果
        enc_results = self.server.homomorphic_check([prefix])
        # 解密结果判断密码是否泄露
        for r in enc_results:
            if self.private_key.decrypt(r) == 1:
                return True
        return False

# 测试
if __name__ == "__main__":
    leaked_passwords = ["123456", "password", "123456789", "qwerty", "abc123"]
    client = Client(None)  # 先创建客户端
    server = Server(leaked_passwords, client.public_key)
    client.server = server  # 绑定服务器

    pwd = input("请输入您的密码：")
    if client.check_password(pwd):
        print("警告：您的密码可能已泄露，请更换密码！")
    else:
        print("您的密码未在已知泄露数据中。")
