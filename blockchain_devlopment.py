import hashlib
import time
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import threading
import socket
import json


def hashgen(data):
    result = hashlib.sha256(data.encode())
    return result.hexdigest()


class User:
    def __init__(self, username, blockchain):
        self.username = username
        self.wallet = Wallet(username)
        blockchain.user_data[self.wallet.address] = self.wallet

    def amount(self):
        return self.wallet


class Transaction:
    def __init__(self, sender, receiver, amount, coin=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.coin = coin  # Add coin attribute
        self.timestamp = int(time.time())


class Coin:
    def __init__(self, name, symbol, initial_supply):
        self.name = name
        self.symbol = symbol
        self.total_supply = initial_supply


class Wallet:
    def __init__(self, username):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.address = self.generate_address()
        self.balance = 0
        self.coins = {}  # Store coins in the wallet
        self.username = username

    def generate_address(self):
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        address = hashlib.sha256(public_key_bytes).digest()

        return base64.b64encode(address).decode('utf-8')

    def save_wallet_details(self):
        wallet_data = f"{self.private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')},{self.public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint).hex()},{self.address},{self.balance}"

        with open("wallet_data.txt", "a") as file:
            file.write(wallet_data + "\n")

    def update_balance(self, amount, coin=None):
        self.balance += amount
        if coin:
            self.coins[coin.symbol] = self.coins.get(coin.symbol, 0) + amount


class Block:
    def __init__(self, index, timestamp, transactions, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = 0
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        block_string = str(self.index) + str(self.timestamp) + str(self.transactions) + str(self.previous_hash)
        return hashgen(block_string)

    def mine_block(self, difficulty):
        prefix = '0' * difficulty
        while self.hash[:difficulty] != prefix:
            self.nonce += 1
            self.hash = self.hash_block()
            self.timestamp = int(time.time())


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.wallet_balances = {}
        self.user_data = {}
        self.peers = set()
        self.coins = {}  # Store available coins in the blockchain

    def create_genesis_block(self):
        return Block(0, int(time.time()), [], "0")

    def add_block_with_consensus(self, transactions_data, difficulty, timeout=10):
        transactions = [
            Transaction(sender=tx['sender'], receiver=tx['receiver'], amount=tx['amount'], coin=tx.get('coin'))
            for tx in transactions_data
        ]

        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), int(time.time()), transactions, previous_block.hash)
        new_block.mine_block(difficulty)
        self.chain.append(new_block)

        time.sleep(timeout)

        if len(self.chain) > new_block.index + 1:
            print("New block was not added to the longest chain")
            self.chain.pop()
            self.chain[-1].hash = self.chain[-1].hash_block()
        else:
            print("New block was added to the longest chain")
            self.update_wallet_balances(transactions)

    def add_transaction(self, transaction):
        self.chain[-1].transactions.append(transaction)
        sender_wallet = self.user_data.get(transaction.sender)
        receiver_wallet = self.user_data.get(transaction.receiver)

        if sender_wallet:
            sender_wallet.update_balance(-transaction.amount, transaction.coin)
        if receiver_wallet:
            receiver_wallet.update_balance(transaction.amount, transaction.coin)

    def update_wallet_balances(self, transactions):
        if isinstance(transactions, Transaction):
            transactions = [transactions]
        for transaction in transactions:
            sender = transaction.sender
            receiver = transaction.receiver
            amount = transaction.amount

            sender_wallet = self.user_data.get(sender)
            receiver_wallet = self.user_data.get(receiver)

            if sender_wallet:
                sender_wallet.update_balance(-amount, transaction.coin)
            if receiver_wallet:
                receiver_wallet.update_balance(amount, transaction.coin)

    def get_wallet_balance(self, address, coin_symbol='SPY'):
        if coin_symbol:
            return self.user_data.get(address).coins.get(coin_symbol, 0) if address in self.user_data else 0
        else:
            return self.user_data.get(address).balance if address in self.user_data else 0

    def broadcast_transaction(self, transaction):
        transaction_data = {
            'sender': transaction.sender,
            'receiver': transaction.receiver,
            'amount': transaction.amount,
            'coin': {
                'name': transaction.coin.name,
                'symbol': transaction.coin.symbol,
                'total_supply': transaction.coin.total_supply
            } if transaction.coin else None
        }
        message = {'type': 'transaction', 'data': transaction_data}
        self.broadcast_message(message)

    def broadcast_message(self, message):
        for peer in self.peers:
            self.send_message(peer, message)

    def send_message(self, peer, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(peer)
            s.sendall(json.dumps(message).encode())


class Node:
    def __init__(self, host, port, blockchain, peers=None):
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.peers = set(peers) if peers else set()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Node started on {self.host}:{self.port}")

       

    

    def send_message(self, peer, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(peer)
            s.sendall(json.dumps(message).encode())

    def broadcast_message(self, message):
        for peer in self.peers:
            self.send_message(peer, message)

    def handle_transaction(self, transaction_data):
        coin_data = transaction_data['coin']
        coin = Coin(name=coin_data['name'], symbol=coin_data['symbol'], initial_supply=coin_data['total_supply']) if coin_data else None

        transaction = Transaction(
            sender=transaction_data['sender'],
            receiver=transaction_data['receiver'],
            amount=transaction_data['amount'],
            coin=coin
        )
        self.blockchain.add_transaction(transaction)

    def handle_block(self, block_data):
        new_block = Block(
            index=block_data['index'],
            transactions=block_data['transactions'],
            previous_hash=block_data['previous_hash'],
            nonce=block_data['nonce'],
            timestamp=block_data['timestamp']
        )
        if self.blockchain.is_valid_proof(
                new_block.index,
                new_block.transactions,
                new_block.previous_hash,
                new_block.nonce,
                new_block.timestamp
        ):
            self.blockchain.add_block(new_block)


# Example usage
if __name__ == "__main__":
    blockchain=Blockchain()
    # Create a new coin and add it to the blockchain
    new_coin = Coin(name="Spy Coin", symbol="SPY", initial_supply=21000000000)
    blockchain.coins[new_coin.symbol] = new_coin

    # Create users
    user1 = User("sachin", blockchain)
    user2 = User("Raj", blockchain)
    
    user1.amount()
    # Create a transaction with the new coin
    transaction = Transaction(sender=user1.wallet.address, receiver=user2.wallet.address, amount=10, coin=new_coin)
    blockchain.add_transaction(transaction)

    print(f"Sachin balance of New Coin: {blockchain.get_wallet_balance(user1.wallet.address, new_coin.symbol)}")
    print(f"Raj balance of New Coin: {blockchain.get_wallet_balance(user2.wallet.address, new_coin.symbol)}")

    # Start nodes
    node1 = Node("localhost", 5000, blockchain, peers=[("localhost", 5001)])
    node2 = Node("localhost", 5001, blockchain)

    node1_thread = threading.Thread(target=node1.start)
    node2_thread = threading.Thread(target=node2.start)
    node1_thread.start()
    node2_thread.start()

    # Broadcast transaction with the new coin
    node1.blockchain.broadcast_transaction(transaction)
    time.sleep(5)
    print("Transactions in Node2's Blockchain:")
    for block in node2.blockchain.chain:
        for tx in block.transactions:
            print(tx.sender, "->", tx.receiver, ":", tx.amount, f"{tx.coin.symbol}")

    # Add blocks to the blockchain with consensus
    node1.blockchain.add_block_with_consensus(
        transactions_data=[{
            'sender': user1.wallet.address,
            'receiver': user2.wallet.address,
            'amount': 10,
            'coin': {
                'name': new_coin.name,
                'symbol': new_coin.symbol,
                'total_supply': new_coin.total_supply
            }
        }],
        difficulty=4
    )

    # Check the wallet balances after consensus
    print(f"User1 balance of New Coin: {blockchain.get_wallet_balance(user1.wallet.address, new_coin.symbol)}")
    print(f"User2 balance of New Coin: {blockchain.get_wallet_balance(user2.wallet.address, new_coin.symbol)}")
