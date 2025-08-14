#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include "sm3.hpp"
#include "merkle.hpp"

// 打印哈希值
void print_hash(const std::vector<uint8_t>& hash){
    for(auto b: hash)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << std::endl;
}

int main(){
    // SM3 哈希测试
    std::string msg = "hello sm3";   // 要进行哈希的原始消息
    SM3 sm3;
    sm3.update((const uint8_t*)msg.c_str(), msg.size()); 
    uint8_t hash[32];
    sm3.final(hash); // 计算哈希结果
    std::vector<uint8_t> hash_vec(hash, hash+32);
    std::cout << "SM3(\"" << msg << "\") = "; 
    print_hash(hash_vec); // 输出SM3哈希结果

    // 长度扩展攻击
    // 设置SM3初始状态
    std::array<uint32_t,8> state = {0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
                                    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E};
    SM3 sm3_le;
    sm3_le.set_state(state, msg.size()*8); // 模拟已经处理过的消息长度
    std::string m2 = " append"; // 要追加的数据
    sm3_le.update((const uint8_t*)m2.c_str(), m2.size());
    uint8_t le_hash[32];
    sm3_le.final(le_hash);
    std::vector<uint8_t> le_hash_vec(le_hash, le_hash+32);
    std::cout << "Length-extension hash = "; 
    print_hash(le_hash_vec); // 输出长度扩展攻击后的哈希

    // 构建 100k 叶子的 Merkle 树
    size_t leaf_count = 100000; 
    std::vector<std::vector<uint8_t>> leaves(leaf_count, std::vector<uint8_t>(32,0));
    for(size_t i=0;i<leaf_count;i++){
        SM3 sm;
        std::string s = "leaf_" + std::to_string(i); // 每个叶子的内容
        sm.update((const uint8_t*)s.c_str(), s.size());
        uint8_t tmp[32];
        sm.final(tmp);
        leaves[i] = std::vector<uint8_t>(tmp, tmp+32); // 保存叶子哈希
    }
    std::cout << "Building Merkle tree..." << std::endl;
    MerkleNode* root = build_merkle_tree(leaves); // 构建Merkle树
    std::cout << "Merkle root hash: "; 
    print_hash(root->hash); // 输出Merkle树根哈希

    // 叶子存在性证明
    size_t leaf_idx = 12345; // 要验证的叶子下标
    auto proof = get_existence_proof(root, leaf_idx, leaf_count); // 获取存在性证明路径
    bool exist_ok = verify_existence(leaves[leaf_idx], proof, leaf_idx, leaf_count, root->hash);
    std::cout << "Existence verification for leaf " << leaf_idx << " : " 
              << (exist_ok ? "PASS" : "FAIL") << std::endl;

    // 叶子不存在性证明
    size_t target_idx = 100001;
    auto nonexist_proof = get_nonexistence_proof(root, leaves, leaf_count, target_idx);
    bool left_ok = verify_existence(nonexist_proof.left_leaf, nonexist_proof.left_proof,
                                   (target_idx==0 ? 0 : target_idx-1), leaf_count, root->hash);
    bool right_ok = verify_existence(nonexist_proof.right_leaf, nonexist_proof.right_proof,
                                    (target_idx >= leaf_count-1 ? leaf_count-1 : target_idx), leaf_count, root->hash);
    std::cout << "Non-existence verification : " 
              << ((left_ok && right_ok) ? "PASS" : "FAIL") << std::endl;

    return 0;
}
