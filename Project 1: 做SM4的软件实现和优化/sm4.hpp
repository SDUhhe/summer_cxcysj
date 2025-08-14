#ifndef SM4_HPP
#define SM4_HPP

#include <cstdint>
#include <array>
#include <immintrin.h>


class SM4 {
public:
    static const int BLOCK_SIZE = 16; 
    // 构造函数
    SM4(const std::array<uint32_t,4>& key);
    // 单块加密
    void encrypt_block(const uint8_t* in, uint8_t* out);
    // AVX2 并行加密，一次处理 num_blocks 个块
    void encrypt_blocks_avx2(const uint8_t* in, uint8_t* out, int num_blocks);

private:
    uint32_t rk[32];                 
    std::array<uint32_t, 256> T_table; 
    // 初始化 T 表
    void init_t_table();
    // 密钥扩展
    void key_expansion(const std::array<uint32_t,4>& key);
    // T 表变换
    uint32_t T_table_transform(uint32_t x);
};

#endif // SM4_HPP
