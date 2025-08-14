#pragma once
#include <array>
#include <vector>
#include <cstdint>

class SM3 {
public:
    static const size_t BLOCK_SIZE = 64;  // SM3分组长度
    static const size_t HASH_SIZE = 32;   // SM3输出哈希长度

    SM3();  // 构造函数，初始化状态
    void reset();  // 重置状态，准备重新计算哈希
    void update(const uint8_t* data, size_t len);  // 向哈希函数输入数据
    void update(const std::vector<uint8_t>& data); // 向哈希函数输入数据（vector版本）
    void final(uint8_t out[HASH_SIZE]);            // 计算最终哈希值

    // 设置中间状态，用于 length-extension attack
    void set_state(const std::array<uint32_t,8>& state, uint64_t bits_processed);

private:
    std::array<uint32_t,8> digest_;  // 当前哈希状态
    uint64_t length_;                // 已处理的总字节数
    uint8_t buffer_[64];             // 缓冲区，用于存储未满一个分组的数据
    size_t buffer_len_;              // 缓冲区已存储的数据长度

    void process_block(const uint8_t block[64]); // 处理一个64字节分组，更新digest_

    static uint32_t rotl(uint32_t x, int n);            // 循环左移n位
    static uint32_t FF(uint32_t x,uint32_t y,uint32_t z,int j); // 带参数的布尔函数
    static uint32_t GG(uint32_t x,uint32_t y,uint32_t z,int j); 
    static uint32_t P0(uint32_t x);                     // 非线性置换函数
    static uint32_t P1(uint32_t x);                     
};
