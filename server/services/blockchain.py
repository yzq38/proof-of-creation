import json
import os
from decimal import Decimal

from web3 import Web3
from web3.exceptions import ContractLogicError

from server.utils.config import NODE_URL, CHAIN_ID, PRIVATE_KEY, CONTRACT_BASIC_ADDRESS, CONTRACT_ADVANCED_ADDRESS
from server.utils.logger import get_logger

logger = get_logger()

_w3: Web3 = None
_account = None

BASIC_ABI = [
    {
        "inputs": [
            {"name": "hash", "type": "bytes32"},
            {"name": "signature1", "type": "bytes32"},
            {"name": "signature2", "type": "bytes32"},
            {"name": "userid", "type": "bytes32"},
        ],
        "name": "basicRecord",
        "outputs": [{"name": "_id", "type": "uint256"}],
        "type": "function",
    },
]

ADVANCED_ABI = [
    {
        "inputs": [
            {"name": "hash", "type": "bytes"},
            {"name": "signature", "type": "bytes"},
            {"name": "userid", "type": "bytes32"},
        ],
        "name": "advancedRecord",
        "outputs": [{"name": "_id", "type": "uint256"}],
        "type": "function",
    },
]


def get_w3() -> Web3:
    global _w3
    if _w3 is None:
        _w3 = Web3(Web3.HTTPProvider(NODE_URL))
        if _w3.is_connected():
            logger.info(f"已连接以太坊节点: {NODE_URL} (chain_id={_w3.eth.chain_id})")
        else:
            logger.warning(f"无法连接以太坊节点: {NODE_URL}")
    return _w3


def get_account():
    global _account
    if _account is None:
        w3 = get_w3()
        _account = w3.eth.account.from_key(PRIVATE_KEY)
        logger.info(f"服务器钱包地址: {_account.address}")
    return _account


def estimate_gas(encryption_mode: str, hash_len: int = 0, sig_len: int = 0) -> int:
    w3 = get_w3()
    account = get_account()
    contract_address = CONTRACT_BASIC_ADDRESS if encryption_mode == "sha3-256+ed25519" else CONTRACT_ADVANCED_ADDRESS
    try:
        if encryption_mode == "sha3-256+ed25519":
            contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=BASIC_ABI)
            tx = contract.functions.basicRecord(
                b"\xff" * 32, b"\xff" * 32, b"\xff" * 32, b"\xff" * 32
            ).build_transaction({
                "from": account.address,
                "chainId": CHAIN_ID,
            })
        else:
            contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=ADVANCED_ABI)
            tx = contract.functions.advancedRecord(
                b"\xff" * max(hash_len, 1), b"\xff" * max(sig_len, 1), b"\xff" * 32
            ).build_transaction({
                "from": account.address,
                "chainId": CHAIN_ID,
            })
        gas = w3.eth.estimate_gas(tx)
        return int(gas * 1.2)
    except Exception as e:
        logger.warning(f"Gas 估算失败: {e}，使用默认值")
        return 150000 if encryption_mode == "sha3-256+ed25519" else 300000


def get_current_gas_price() -> dict:
    w3 = get_w3()
    try:
        fee_data = w3.eth.fee_history(1, "latest", [25, 50, 75])
        base_fee = fee_data["baseFeePerGas"][-1]
        priority_fees = fee_data.get("reward", [[0]])[-1]
        median_priority = int(sum(priority_fees) / len(priority_fees)) if priority_fees else 1_500_000_000
        max_fee = base_fee + median_priority * 2
        return {
            "base_fee": base_fee,
            "max_priority_fee": median_priority,
            "max_fee_per_gas": max_fee,
            "last_base_fee": base_fee,
        }
    except Exception as e:
        logger.warning(f"获取 Gas 价格失败: {e}，使用默认值")
        return {
            "base_fee": 20_000_000_000,
            "max_priority_fee": 1_500_000_000,
            "max_fee_per_gas": 30_000_000_000,
            "last_base_fee": 20_000_000_000,
        }


def send_transaction(encryption_mode: str, data: dict, gas_limit: int, max_fee_per_gas: int, max_priority_fee: int) -> str:
    w3 = get_w3()
    account = get_account()
    contract_address = CONTRACT_BASIC_ADDRESS if encryption_mode == "sha3-256+ed25519" else CONTRACT_ADVANCED_ADDRESS

    if encryption_mode == "sha3-256+ed25519":
        contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=BASIC_ABI)
        func = contract.functions.basicRecord(
            data["hash"],
            data["signature1"],
            data["signature2"],
            data["user_id"],
        )
    else:
        contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=ADVANCED_ABI)
        func = contract.functions.advancedRecord(
            data["hash"],
            data["signature"],
            data["user_id"],
        )

    nonce = w3.eth.get_transaction_count(account.address, "pending")
    tx = func.build_transaction({
        "from": account.address,
        "chainId": CHAIN_ID,
        "gas": gas_limit,
        "maxFeePerGas": max_fee_per_gas,
        "maxPriorityFeePerGas": max_priority_fee,
        "nonce": nonce,
    })

    nonce = w3.eth.get_transaction_count(account.address, "pending")

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hash_hex = "0x" + tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash
    logger.info(f"交易已发送: {tx_hash_hex}")
    return tx_hash_hex


def wait_for_receipt(tx_hash: str, timeout: int = 300) -> dict:
    w3 = get_w3()
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    return {
        "block_number": receipt["blockNumber"],
        "gas_used": receipt["gasUsed"],
        "effective_gas_price": receipt["effectiveGasPrice"],
        "status": receipt["status"],
    }
