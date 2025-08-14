import hashlib
import hmac
import os
from typing import Tuple

# SM2 曲线参数
p = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)
a = int("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16)
b = int("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16)
Gx = int("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16)
Gy = int("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16)
n = int("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16)

# 计算模逆
def mod_inv(x: int, m: int = p) -> int:
    return pow(x % m, m - 2, m)

# 检查点是否在曲线上
def is_on_curve(P: Tuple[int,int]) -> bool:
    if P is None:
        return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

# 椭圆曲线点加法
def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

# 标量乘法
def scalar_mul(k: int, P):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

# 哈希函数
def H(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def bytes_from_int(i: int, length: int = 32) -> bytes:
    return i.to_bytes(length, 'big')

G = (Gx, Gy)

# 生成私钥和公钥
def keygen() -> Tuple[int, Tuple[int,int]]:
    d = int_from_bytes(os.urandom(32)) % n
    if d == 0:
        return keygen()
    P = scalar_mul(d, G)
    return d, P

# SM2 签名
def sm2_sign(d: int, ZA_plus_M: bytes, k: int = None) -> Tuple[int,int,int]:
    if k is None:
        k = int_from_bytes(os.urandom(32)) % n
        if k == 0:
            return sm2_sign(d, ZA_plus_M, None)
    R = scalar_mul(k, G)
    x1, y1 = R
    e = int_from_bytes(H(ZA_plus_M))
    r = (e + x1) % n
    if r == 0 or (r + k) % n == 0:
        return sm2_sign(d, ZA_plus_M, None)
    inv = mod_inv(1 + d, n)
    s = (inv * (k - r * d)) % n
    if s == 0:
        return sm2_sign(d, ZA_plus_M, None)
    return r, s, k

# 验证 SM2 签名
def sm2_verify(P: Tuple[int,int], ZA_plus_M: bytes, r: int, s: int) -> bool:
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    e = int_from_bytes(H(ZA_plus_M))
    t = (r + s) % n
    if t == 0:
        return False
    x1y1 = point_add(scalar_mul(s, G), scalar_mul(t, P))
    if x1y1 is None:
        return False
    x1, _ = x1y1
    return (e + x1) % n == r

# 确定性k
def generate_k(d: int, h1: bytes) -> int:
    qlen = n.bit_length()
    hlen = 32
    bx = bytes_from_int(d, 32) + h1
    V = b'\x01' * hlen
    K = b'\x00' * hlen
    K = hmac.new(K, V + b'\x00' + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b'\x01' + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        T = b''
        while len(T) < (qlen + 7) // 8:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = int_from_bytes(T) >> (len(T)*8 - qlen)
        k = k % n
        if 1 <= k <= n-1:
            return k
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()

# 已知 k 恢复私钥
def recover_d_from_leaked_k(r: int, s: int, k: int) -> int:
    denom = (r + s) % n
    if denom == 0:
        raise ValueError("分母为零")
    return ((k - s) * mod_inv(denom, n)) % n

# 两条签名使用相同 k 恢复私钥
def recover_d_from_two_sigs_same_k(r1, s1, r2, s2) -> int:
    num = (s2 - s1) % n
    den = (s1 - s2 + r1 - r2) % n
    if den == 0:
        raise ValueError("分母为零")
    return (num * mod_inv(den, n)) % n

# 跨算法复用 k 恢复私钥
def recover_d_from_sm2_and_ecdsa(r_ecdsa, s_ecdsa, e_ecdsa, r_sm2, s_sm2, e_sm2) -> int:
    num = (s_ecdsa * s_sm2 - e_ecdsa) % n
    den = (r_ecdsa - s_ecdsa * s_sm2 - s_ecdsa * r_sm2) % n
    if den == 0:
        raise ValueError("分母为零")
    return (num * mod_inv(den, n)) % n


def demo():
    print("SM2 演示开始...")
    dA, PA = keygen()
    print("公钥在曲线上:", is_on_curve(PA))

    M1 = b"message one"
    ZA_plus_M1 = M1

    r1, s1, k1 = sm2_sign(dA, ZA_plus_M1)
    print("签名1验证:", sm2_verify(PA, ZA_plus_M1, r1, s1))

    recovered_d = recover_d_from_leaked_k(r1, s1, k1)
    print("泄露 k 恢复私钥正确:", recovered_d == dA)

    M2 = b"message two (different)"
    r2, s2, k2 = sm2_sign(dA, M2, k=k1)
    print("签名2验证:", sm2_verify(PA, M2, r2, s2))
    d_from_two = recover_d_from_two_sigs_same_k(r1, s1, r2, s2)
    print("相同 k 恢复私钥正确:", d_from_two == dA)

    M3 = b"cross scheme message"
    e_ecdsa = int_from_bytes(H(M3))
    R = scalar_mul(k1, G)
    r_ecdsa = R[0] % n
    s_ecdsa = (mod_inv(k1, n) * (e_ecdsa + r_ecdsa * dA)) % n
    e_sm2 = int_from_bytes(H(M3))
    r_sm2, s_sm2, _ = sm2_sign(dA, M3, k=k1)
    d_recovered_cross = recover_d_from_sm2_and_ecdsa(r_ecdsa, s_ecdsa, e_ecdsa, r_sm2, s_sm2, e_sm2)
    print("跨算法 k 恢复私钥正确:", d_recovered_cross == dA)

    h1 = H(b"deterministic message")
    kd = generate_k(dA, h1)
    r_d, s_d, _ = sm2_sign(dA, b"deterministic message", k=kd)
    print("确定性 k 签名验证:", sm2_verify(PA, b"deterministic message", r_d, s_d))

    print("演示结束。")

if __name__ == "__main__":
    demo()
