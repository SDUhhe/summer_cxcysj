#include "merkle.hpp"
#include <iostream>


MerkleNode* build_merkle_tree(const std::vector<std::vector<uint8_t>>& leaves){
    std::vector<MerkleNode*> nodes;
    // 先把所有叶子包装成 MerkleNode
    for(auto& leaf : leaves) nodes.push_back(new MerkleNode(leaf));

    // 循环构建父节点，直到只剩下根节点
    while(nodes.size()>1){
        std::vector<MerkleNode*> parents;
        for(size_t i=0;i<nodes.size();i+=2){
            auto left = nodes[i];
            auto right = (i+1<nodes.size())?nodes[i+1]:left; // 如果奇数个节点，右节点重复左节点

            SM3 sm3;
            uint8_t tmp[32];
            std::vector<uint8_t> data;
            data.push_back(0x01); 
            data.insert(data.end(), left->hash.begin(), left->hash.end());
            data.insert(data.end(), right->hash.begin(), right->hash.end());
            sm3.update(data);
            sm3.final(tmp);

            // 创建父节点
            parents.push_back(new MerkleNode(std::vector<uint8_t>(tmp,tmp+32)));
            parents.back()->left = left;
            parents.back()->right = right;
        }
        nodes = parents; 
    }
    return nodes[0]; 
}


std::vector<std::vector<uint8_t>> get_existence_proof(MerkleNode* root, size_t index, size_t leaf_count){
    std::vector<std::vector<uint8_t>> proof;
    size_t start=0, end=leaf_count-1;
    MerkleNode* node = root;

    // 从根到叶子路径，每层加入兄弟节点哈希
    while(node->left && node->right){
        size_t mid = start + (end-start)/2;
        if(index <= mid){
            proof.push_back(node->right->hash); 
            node = node->left;
            end = mid;
        }else{
            proof.push_back(node->left->hash);  
            node = node->right;
            start = mid+1;
        }
    }
    return proof;
}


bool verify_existence(const std::vector<uint8_t>& leaf_hash,
                      const std::vector<std::vector<uint8_t>>& proof,
                      size_t index, size_t leaf_count,
                      const std::vector<uint8_t>& root_hash){
    std::vector<uint8_t> hash = leaf_hash;
    size_t start=0,end=leaf_count-1;

    // 沿路径依次合并兄弟节点，重新计算父节点哈希
    for(auto& sibling_hash : proof){
        std::vector<uint8_t> combined;
        size_t mid = start + (end-start)/2;
        combined.push_back(0x01); 
        if(index <= mid){
            combined.insert(combined.end(), hash.begin(), hash.end());
            combined.insert(combined.end(), sibling_hash.begin(), sibling_hash.end());
            end = mid;
        }else{
            combined.insert(combined.end(), sibling_hash.begin(), sibling_hash.end());
            combined.insert(combined.end(), hash.begin(), hash.end());
            start = mid+1;
        }
        SM3 sm;
        sm.update(combined);
        uint8_t tmp[32];
        sm.final(tmp);
        hash = std::vector<uint8_t>(tmp,tmp+32);
    }

    // 最终计算出的哈希是否等于根哈希
    return hash == root_hash;
}

NonExistenceProof get_nonexistence_proof(MerkleNode* root,
                                        const std::vector<std::vector<uint8_t>>& leaves,
                                        size_t leaf_count,
                                        size_t target_index){
    NonExistenceProof proof;

    // 左边最近存在的叶子索引
    size_t left_index = (target_index==0)?0:target_index-1;
    // 右边最近存在的叶子索引
    size_t right_index = (target_index>=leaf_count-1)?leaf_count-1:target_index;

    // 左边叶子及其存在性证明
    proof.left_leaf = leaves[left_index];
    proof.left_proof = get_existence_proof(root,left_index,leaf_count);

    // 右边叶子及其存在性证明
    proof.right_leaf = leaves[right_index];
    proof.right_proof = get_existence_proof(root,right_index,leaf_count);

    return proof;
}
