#include "sm3.hpp"
#include <cstring>


SM3::SM3() { reset(); } // 构造函数，初始化状态

// 重置内部状态，准备计算新的哈希
void SM3::reset() {
    digest_ = { 0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
                0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E };
    length_ = 0;       
    buffer_len_ = 0;   
}

// 向哈希函数输入数据
void SM3::update(const uint8_t* data, size_t len) {
    size_t i=0;
    while(i<len){
        buffer_[buffer_len_++] = data[i++]; 
        if(buffer_len_==BLOCK_SIZE){        
            process_block(buffer_);        
            buffer_len_=0;              
        }
    }
    length_ += len*8; 
}

// vector版本的update
void SM3::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

// 完成哈希计算，输出32字节结果
void SM3::final(uint8_t out[HASH_SIZE]){
    uint64_t total_bits = length_;   
    buffer_[buffer_len_++] = 0x80;   
    if(buffer_len_>56){             
        while(buffer_len_<64) buffer_[buffer_len_++] = 0x00; 
        process_block(buffer_);     
        buffer_len_=0;
    }
    while(buffer_len_<56) buffer_[buffer_len_++] = 0x00; 
    // 填充长度字段
    for(int i=7;i>=0;i--)
        buffer_[buffer_len_++] = (total_bits >> (i*8)) & 0xFF;
    process_block(buffer_);

    // 输出哈希值
    for(int i=0;i<8;i++){
        out[i*4+0] = (digest_[i]>>24)&0xFF;
        out[i*4+1] = (digest_[i]>>16)&0xFF;
        out[i*4+2] = (digest_[i]>>8)&0xFF;
        out[i*4+3] = digest_[i]&0xFF;
    }
}

// 设置中间状态，用于 length-extension attack
void SM3::set_state(const std::array<uint32_t,8>& state, uint64_t bits_processed){
    digest_ = state;    
    length_ = bits_processed; 
    buffer_len_ = 0;
}

// 循环左移n位
uint32_t SM3::rotl(uint32_t x,int n){ return (x<<n)|(x>>(32-n)); }

// 布尔函数，根据轮数选择公式
uint32_t SM3::FF(uint32_t x,uint32_t y,uint32_t z,int j){ 
    return (j<=15)?(x^y^z):((x&y)|(x&z)|(y&z)); 
}

uint32_t SM3::GG(uint32_t x,uint32_t y,uint32_t z,int j){ 
    return (j<=15)?(x^y^z):((x&y)|(~x&z)); 
}

// 置换函数
uint32_t SM3::P0(uint32_t x){ return x^rotl(x,9)^rotl(x,17); }

uint32_t SM3::P1(uint32_t x){ return x^rotl(x,15)^rotl(x,23); }

// 处理一个64字节分组
void SM3::process_block(const uint8_t block[64]){
    uint32_t W[68], W1[64];
    for(int i=0;i<16;i++)
        W[i] = (block[i*4]<<24)|(block[i*4+1]<<16)|(block[i*4+2]<<8)|block[i*4+3];
    for(int i=16;i<68;i++)
        W[i] = P1(W[i-16]^W[i-9]^rotl(W[i-3],15))^rotl(W[i-13],7)^W[i-6];
    for(int i=0;i<64;i++) W1[i] = W[i]^W[i+4];

    // 初始化寄存器
    uint32_t A=digest_[0],B=digest_[1],C=digest_[2],D=digest_[3];
    uint32_t E=digest_[4],F=digest_[5],G=digest_[6],H=digest_[7];

    // 主循环64轮
    for(int j=0;j<64;j++){
        uint32_t Tj = (j<=15)?0x79CC4519:0x7A879D8A; 
        uint32_t SS1 = rotl((rotl(A,12)+E+rotl(Tj,j))&0xFFFFFFFF,7);
        uint32_t SS2 = SS1^rotl(A,12);
        uint32_t TT1 = (FF(A,B,C,j)+D+SS2+W1[j])&0xFFFFFFFF;
        uint32_t TT2 = (GG(E,F,G,j)+H+SS1+W[j])&0xFFFFFFFF;
        // 更新寄存器
        D=C; C=rotl(B,9); B=A; A=TT1;
        H=G; G=rotl(F,19); F=E; E=P0(TT2);
    }

    // 与前一状态异或，更新digest_
    digest_[0]^=A; digest_[1]^=B; digest_[2]^=C; digest_[3]^=D;
    digest_[4]^=E; digest_[5]^=F; digest_[6]^=G; digest_[7]^=H;
}
