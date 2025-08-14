#pragma once
#include "sm3.hpp"
#include <vector>

// Merkle 树节点
struct MerkleNode {
    std::vector<uint8_t> hash; 
    MerkleNode* left;           
    MerkleNode* right;        
    MerkleNode(std::vector<uint8_t> h) : hash(h), left(nullptr), right(nullptr) {}
};

// 构建 Merkle 树
MerkleNode* build_merkle_tree(const std::vector<std::vector<uint8_t>>& leaves);

// 获取某个叶子的存在性证明
std::vector<std::vector<uint8_t>> get_existence_proof(MerkleNode* root, size_t index, size_t leaf_count);

// 验证存在性证明
bool verify_existence(const std::vector<uint8_t>& leaf_hash,
                      const std::vector<std::vector<uint8_t>>& proof,
                      size_t index, size_t leaf_count,
                      const std::vector<uint8_t>& root_hash);

// 非存在性证明结构体
struct NonExistenceProof {
    std::vector<uint8_t> left_leaf;                // 左边最近存在的叶子
    std::vector<std::vector<uint8_t>> left_proof;  // 左边叶子的存在性证明
    std::vector<uint8_t> right_leaf;               // 右边最近存在的叶子
    std::vector<std::vector<uint8_t>> right_proof; // 右边叶子的存在性证明
};

// 获取非存在性证明
NonExistenceProof get_nonexistence_proof(MerkleNode* root,
                                         const std::vector<std::vector<uint8_t>>& leaves,
                                         size_t leaf_count,
                                         size_t target_index);
