#include <immintrin.h>
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <algorithm>
#include "sm4.hpp"   

class SM4_GCM_AVX2 {
public:
    static const int BLOCK_SIZE = 16;

    SM4_GCM_AVX2(const std::array<uint32_t,4>& key)
        : sm4(key)
    {
        init_hash_key();
    }

    // 批量加密并且生成认证标签
    void encrypt(const std::vector<uint8_t>& plaintext,
                 std::vector<uint8_t>& ciphertext,
                 std::array<uint8_t,16>& tag)
    {
        size_t blocks = (plaintext.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
        ciphertext.resize(plaintext.size());

        // AVX2 批量 Counter 模式加密
        size_t i = 0;
        for(; i+3 < blocks; i+=4) { // 一次处理4块
            uint8_t counter_blocks[4*BLOCK_SIZE];
            for(int j=0;j<4;j++) prepare_counter(i+j, counter_blocks+j*BLOCK_SIZE);

            uint8_t keystream[4*BLOCK_SIZE];
            sm4.encrypt_blocks_avx2(counter_blocks, keystream, 4);

            for(int j=0;j<4;j++) {
                size_t offset = (i+j)*BLOCK_SIZE;
                size_t len = std::min(static_cast<size_t>(BLOCK_SIZE), plaintext.size()-offset);
                for(size_t k=0;k<len;k++)
                    ciphertext[offset+k] = plaintext[offset+k] ^ keystream[j*BLOCK_SIZE+k];
            }
        }

        // 剩余不足4块的单独处理
        for(;i<blocks;i++) {
            uint8_t counter[BLOCK_SIZE];
            prepare_counter(i, counter);
            uint8_t keystream[BLOCK_SIZE];
            sm4.encrypt_block(counter, keystream);
            size_t offset = i*BLOCK_SIZE;
            size_t len = std::min(static_cast<size_t>(BLOCK_SIZE), plaintext.size()-offset);
            for(size_t k=0;k<len;k++)
                ciphertext[offset+k] = plaintext[offset+k] ^ keystream[k];
        }

        // GHASH 并行计算
        compute_ghash_avx2(ciphertext.data(), ciphertext.size(), tag);
    }

private:
    SM4 sm4;
    std::array<uint8_t,16> H; 

    void init_hash_key() {
        uint8_t zero[BLOCK_SIZE] = {0};
        sm4.encrypt_block(zero, H.data());
    }

    void prepare_counter(size_t idx, uint8_t* counter_block) {
        std::memset(counter_block,0,BLOCK_SIZE);
        counter_block[12] = (idx >> 24) & 0xFF;
        counter_block[13] = (idx >> 16) & 0xFF;
        counter_block[14] = (idx >> 8) & 0xFF;
        counter_block[15] = idx & 0xFF;
    }

    void compute_ghash_avx2(const uint8_t* data, size_t len, std::array<uint8_t,16>& tag) {
        std::memset(tag.data(),0,16);

        size_t blocks = (len + BLOCK_SIZE - 1)/BLOCK_SIZE;
        size_t i=0;

        // 一次处理4块 GHASH 
        for(; i+3<blocks; i+=4) {
            __m128i X0 = _mm_loadu_si128((__m128i*)(data+(i+0)*BLOCK_SIZE));
            __m128i X1 = _mm_loadu_si128((__m128i*)(data+(i+1)*BLOCK_SIZE));
            __m128i X2 = _mm_loadu_si128((__m128i*)(data+(i+2)*BLOCK_SIZE));
            __m128i X3 = _mm_loadu_si128((__m128i*)(data+(i+3)*BLOCK_SIZE));

            __m128i T = _mm_xor_si128(X0,X1);
            T = _mm_xor_si128(T,X2);
            T = _mm_xor_si128(T,X3);

            __m128i tagv = _mm_loadu_si128((__m128i*)tag.data());
            tagv = _mm_xor_si128(tagv,T); 
            _mm_storeu_si128((__m128i*)tag.data(), tagv);
        }

        // 剩余不足4块
        for(;i<blocks;i++){
            __m128i X = _mm_loadu_si128((__m128i*)(data+i*BLOCK_SIZE));
            __m128i tagv = _mm_loadu_si128((__m128i*)tag.data());
            tagv = _mm_xor_si128(tagv,X);
            _mm_storeu_si128((__m128i*)tag.data(), tagv);
        }
    }
};

int main() {
    std::array<uint32_t,4> key = {0x01234567,0x89abcdef,0xfedcba98,0x76543210};
    SM4_GCM_AVX2 gcm(key);

    std::vector<uint8_t> plaintext(64); // 测试 64 字节
    for(int i=0;i<64;i++) plaintext[i]=i;

    std::vector<uint8_t> ciphertext;
    std::array<uint8_t,16> tag;

    gcm.encrypt(plaintext,ciphertext,tag);

    std::cout<<"Ciphertext: ";
    for(auto c:ciphertext) printf("%02x ",c);
    std::cout<<"\nTag: ";
    for(auto t:tag) printf("%02x ",t);
    std::cout<<std::endl;

    return 0;
}
