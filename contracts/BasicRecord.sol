// BasicRecord.sol
pragma solidity ^0.8.0;

contract BasicRecord {
    uint256 public id;
    mapping(uint256 => bytes32) public Hash;
    mapping(uint256 => bytes32) public Signature1;
    mapping(uint256 => bytes32) public Signature2;
    mapping(uint256 => bytes32) public UserID;

    function basicRecord(bytes32 hash, bytes32 signature1, bytes32 signature2, bytes32 userid) external returns (uint256 _id) {
        _id = ++id;
        Hash[_id] = hash;                // 文件的SHA3-256哈希的32字节
        Signature1[_id] = signature1;    // hash的Ed25519签名的前32字节
        Signature2[_id] = signature2;    // hash的Ed25519签名的后32字节
        UserID[_id] = userid;            // Ed25519公钥的SHA3-256哈希的32字节
    }
}