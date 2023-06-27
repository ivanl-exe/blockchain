from hashlib import sha256
from base58 import b58encode, b58decode
from time import time
from os import urandom

class Transaction:
    def __init__(self, hash: bytes, data, timestamp: int) -> None:
        self.hash = hash
        self.data = data
        self.timestamp = timestamp
    
    
    def __repr__(self) -> str:
        return f'"{self.data}"'
 
class Block:
    def __init__(self, hash: bytes, difficulty: int, data, nonce: bytes, timestamp: int) -> None:
        self.hash = hash
        self.data = data
        self.nonce = nonce
        self.timestamp = timestamp
        self.difficulty = difficulty
    
    def __repr__(self) -> str:
        return 'Hash: {}\nDifficulty: {}\n(TXN) Data: {}\nNonce: {}\nTimestamp: {}'.format(
            Blockchain.__encode__(self.hash),
            self.difficulty,
            self.data,
            Blockchain.__encode__(self.nonce),
            self.timestamp,
        )

class Blockchain(Block, Transaction):
    def __init__(self, genesis_message: str = 'genesis') -> None:
        self.chain = []
        self.pool = []
        self.difficulty = 0
        self.__genesis__(genesis_message)
    
    def __encodable__(arg, encoding: str = 'utf-8') -> bytes:
        if type(arg) != bytes : return str(arg).encode(encoding)
        return arg
    
    def __encode__(arg: bytes, encoding: str = 'utf-8') -> str:
        return b58encode(arg).decode(encoding)

    def __hash__(*args) -> str:
        data = b''.join(map(Blockchain.__encodable__, args))
        return sha256(data).digest()

    def __timestamp__() -> int:
        return time()
    
    def nonce(n: int = 32) -> bytes:
        return urandom(n)

    def transaction(self, data: str) -> None:
        salt = ''
        if len(self.pool) > 0: salt = self.pool[-1].hash
        elif len(self.chain) > 0: salt = self.chain[-1].hash
        timestamp = Blockchain.__timestamp__()
        hash = Blockchain.__hash__(data, salt, timestamp)
        txn = Transaction(hash, data, timestamp)
        self.pool.append(txn)
        return txn

    def add_block(self, nonce: bytes = None) -> None:
        salt = ''
        if len(self.chain) >= 1: salt = self.chain[-1].hash
        if nonce == None: nonce = Blockchain.nonce()
        timestamp = Blockchain.__timestamp__()
        data = [txn.hash for txn in self.pool]
        hash = Blockchain.__hash__(*data, salt, nonce, timestamp)
        if all([n == 0 for n in hash[:self.difficulty]]):
            block = Block(hash, self.difficulty, self.pool, nonce, timestamp)
            self.chain.append(block)
            self.pool = []
        return hash
    
    def __genesis__(self, *messages) -> None:
        [self.transaction(message) for message in messages]
        self.add_block()

    def is_valid(self) -> bool:
        try:
            for i in range(len(self.chain) - 1, -1, -1):
                block = self.chain[i]
                for j in range(len(block.data) - 1, -1, -1):
                    txn = block.data[j]
                    previous_hash = ''
                    if (j - 1) >= 0: previous_hash = block.data[j-1].hash
                    elif (i - 1) >= 0: previous_hash = self.chain[i-1].hash
                    if Blockchain.__hash__(txn.data, previous_hash, txn.timestamp) != txn.hash: return False
                previous_hash = ''
                if (i - 1) >= 0: previous_hash = self.chain[i-1].hash
                data = [txn.hash for txn in block.data]
                if Blockchain.__hash__(*data, previous_hash, block.nonce, block.timestamp) != block.hash: return False
            return True
        except:
            return False
        
    
    def __repr__(self) -> str:
        return '\n\n'.join([str(block) for block in self.chain])