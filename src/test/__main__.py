from blockchain import *

if __name__ == '__main__':
    blockchain = Blockchain()
    blockchain.difficulty = 2
    blockchain.transaction("Hello, world!")
    blockchain.transaction("Goodbye, world.")
    
    while len(blockchain.pool) > 0:
        nonce = Blockchain.nonce()
        hash = blockchain.add_block(nonce)

    print(blockchain)
    
    print()
    if blockchain.is_valid():
        print('Valid blockchain')
    else:
        print('Invalid blockchain')