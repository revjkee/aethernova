# onchain/treasury_allocator.py

from decimal import Decimal
import logging
from web3 import Web3
from web3.exceptions import ContractLogicError, TransactionNotFound
from utils.abi_loader import load_contract_abi
from utils.config import get_config_value
from utils.retry import retry_on_failure

logger = logging.getLogger("TreasuryAllocator")
logger.setLevel(logging.INFO)

class TreasuryAllocator:
    def __init__(self, w3: Web3):
        self.w3 = w3
        self.dao_address = Web3.to_checksum_address(get_config_value("DAO_CONTRACT"))
        self.treasury_address = Web3.to_checksum_address(get_config_value("TREASURY_CONTRACT"))
        self.token_address = Web3.to_checksum_address(get_config_value("TOKEN_CONTRACT"))
        self.account = Web3.to_checksum_address(get_config_value("SENDER_ADDRESS"))

        self.token = self._load_contract("ERC20", self.token_address)
        self.dao_contract = self._load_contract("DAO", self.dao_address)
        self.treasury_contract = self._load_contract("Treasury", self.treasury_address)

    def _load_contract(self, name: str, address: str):
        abi = load_contract_abi(name)
        return self.w3.eth.contract(address=address, abi=abi)

    @retry_on_failure(retries=3, delay=5)
    def trigger_distribution(self, total_amount: Decimal):
        if total_amount <= 0:
            logger.warning("[TreasuryAllocator] Attempt to distribute zero tokens.")
            return

        amount_wei = int(total_amount * (10 ** 18))
        validator_share = int(amount_wei * 0.3)
        dao_share = amount_wei - validator_share

        logger.info(f"[TreasuryAllocator] Starting distribution: total={amount_wei}, "
                    f"validator={validator_share}, dao={dao_share}")

        try:
            tx1 = self._transfer_to_contract(self.dao_contract, dao_share, "DAO")
            tx2 = self._transfer_to_contract(self.treasury_contract, validator_share, "ValidatorFund")

            logger.info(f"[TreasuryAllocator] Distribution complete: DAO tx={tx1}, Validator tx={tx2}")
            return tx1, tx2

        except (ContractLogicError, TransactionNotFound) as e:
            logger.error(f"[TreasuryAllocator] Distribution failed: {e}")
            raise

    def _transfer_to_contract(self, contract, amount: int, label: str) -> str:
        tx = self.token.functions.transfer(contract.address, amount).build_transaction({
            'from': self.account,
            'nonce': self.w3.eth.get_transaction_count(self.account),
            'gas': 120000,
            'gasPrice': self.w3.to_wei('30', 'gwei')
        })
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=get_config_value("PRIVATE_KEY"))
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logger.info(f"[TreasuryAllocator] {label} transfer submitted: tx_hash={tx_hash.hex()}")
        return tx_hash.hex()
