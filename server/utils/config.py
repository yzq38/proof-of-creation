import os
from dotenv import load_dotenv
from decimal import Decimal

load_dotenv()

NODE_URL = os.getenv("NODE_URL", "https://ethereum-sepolia-rpc.publicnode.com")
CHAIN_ID = int(os.getenv("CHAIN_ID", "11155111"))
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")
CONTRACT_BASIC_ADDRESS = os.getenv("CONTRACT_BASIC_ADDRESS", "0xA2BC43AA22D46Bb56934a2671871eA0d16E99AC3")
CONTRACT_ADVANCED_ADDRESS = os.getenv("CONTRACT_ADVANCED_ADDRESS", "0xc495633D2a960AC7fF5dd9318D747e9Bb7D67f23")
FIXED_FEE = Decimal(os.getenv("FIXED_FEE", "0.20"))
FEE_RATE = Decimal(os.getenv("FEE_RATE", "0.05"))
MIN_GAS_MULTIPLIER = float(os.getenv("MIN_GAS_MULTIPLIER", "1.2"))
PRICE_MULTIPLIER = Decimal(os.getenv("PRICE_MULTIPLIER", "1.5"))
ORDER_EXPIRY = int(os.getenv("ORDER_EXPIRY", "60"))
EXCHANGE_RATE_API = os.getenv("EXCHANGE_RATE_API", "https://cny.rate.sx/1eth")
EXCHANGE_CACHE_TTL = int(os.getenv("EXCHANGE_CACHE_TTL", "30"))
FALLBACK_RATE = Decimal(os.getenv("FALLBACK_RATE", "15000"))
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-in-production!")
JWT_EXPIRY = int(os.getenv("JWT_EXPIRY", "86400"))
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/poc.db")
LOG_DIR = os.getenv("LOG_DIR", "logs")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
SSL_CERT = os.getenv("SSL_CERT", "")
SSL_KEY = os.getenv("SSL_KEY", "")


def check_config():
    errors = []
    required_str = {
        "NODE_URL": NODE_URL,
        "PRIVATE_KEY": PRIVATE_KEY,
        "CONTRACT_BASIC_ADDRESS": CONTRACT_BASIC_ADDRESS,
        "CONTRACT_ADVANCED_ADDRESS": CONTRACT_ADVANCED_ADDRESS,
        "EXCHANGE_RATE_API": EXCHANGE_RATE_API,
        "JWT_SECRET": JWT_SECRET,
    }
    for name, value in required_str.items():
        if not value or "your-" in value or "0000" in value:
            errors.append(f"{name} 未配置或为占位符")
    if errors:
        raise RuntimeError("配置检查失败:\n" + "\n".join(f"  - {e}" for e in errors))
