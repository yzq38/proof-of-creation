import os
import sys
import json

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from solcx import compile_source, install_solc
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from server.utils.config import NODE_URL, CHAIN_ID, PRIVATE_KEY

CONTRACTS_DIR = os.path.join(project_root, "contracts")


def load_sol(name: str) -> str:
    path = os.path.join(CONTRACTS_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def deploy():
    install_solc("0.8.19")
    w3 = Web3(Web3.HTTPProvider(NODE_URL))
    if CHAIN_ID == 11155111:
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        print("无法连接以太坊节点:", NODE_URL)
        sys.exit(1)

    account = w3.eth.account.from_key(PRIVATE_KEY)
    print(f"部署账户: {account.address}")
    print(f"余额: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")

    contracts = {
        "BasicRecord": "BasicRecord.sol",
        "AdvancedRecord": "AdvancedRecord.sol",
    }

    for name, filename in contracts.items():
        source = load_sol(filename)
        compiled = compile_source(source, solc_version="0.8.19", output_values=["abi", "bin"])
        contract_id = f"<stdin>:{name}"
        contract_interface = compiled[contract_id]

        abi = contract_interface["abi"]
        bytecode = contract_interface["bin"]

        contract = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx = contract.constructor().build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gasPrice": w3.eth.gas_price,
        })

        gas = w3.eth.estimate_gas(tx)
        tx["gas"] = int(gas * 1.2)

        signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"{name} 部署中... tx: 0x{tx_hash.hex()}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        print(f"{name} 已部署到: {receipt['contractAddress']}")
        print(f"  Gas用量: {receipt['gasUsed']}")
        print(f"  区块高度: {receipt['blockNumber']}")

        env_path = os.path.join(project_root, ".env")
        key = "CONTRACT_BASIC_ADDRESS" if name == "BasicRecord" else "CONTRACT_ADVANCED_ADDRESS"
        update_env(env_path, key, receipt["contractAddress"])

    print("\n部署完成，.env 已更新")


def update_env(path: str, key: str, value: str):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    updated = []
    for line in lines:
        if line.startswith(key + "="):
            updated.append(f"{key}={value}\n")
        else:
            updated.append(line)
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(updated)


if __name__ == "__main__":
    deploy()
