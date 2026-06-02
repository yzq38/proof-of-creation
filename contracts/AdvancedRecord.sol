// AdvancedRecord.sol
pragma solidity ^0.8.0;

contract AdvancedRecord {
    uint256 public id;
    mapping(uint256 => bytes) public Hash;
    mapping(uint256 => bytes) public Signature;
    mapping(uint256 => bytes32) public UserID;

    function advancedRecord(bytes calldata hash, bytes calldata signature, bytes32 userid) external returns (uint256 _id) {
        _id = ++id;
        Hash[_id] = hash;                // 文件的哈希的所有字节
        Signature[_id] = signature;      // hash的签名的所有字节
        UserID[_id] = userid;            // 公钥的SHA3-256哈希的32字节
    }
}