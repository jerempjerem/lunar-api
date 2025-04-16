import requests
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256

class LunarClient:
    def __init__(self, host="http://localhost:9192", password=""):
        """Initialize the Lunar API client
        
        Args:
            host (str): The API host URL
            password (str): Your lunar password
        """
        self.host = host.rstrip('/')
        self.password = password
        self.challenge_response = None
        
    def _aes256(self, plaintext, password, salt, iv):
        """Encrypt data using AES-256-CBC with PBKDF2"""

        key = PBKDF2(
            password.encode(), 
            salt,
            dkLen=32,  # 256 bits
            count=10000,
            hmac_hash_module=SHA256
        )
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        combined = salt + iv + ciphertext
        return ''.join([f'{b:02x}' for b in combined])

    def login(self):
        """Perform the challenge-response authentication"""

        r = requests.get(f"{self.host}/get-challenge", headers={"ngrok-skip-browser-warning": "1"})
        if not r.ok:
            raise Exception("Failed to get login challenge")

        challenge_data = r.json()
        
        challenge = challenge_data['challenge']
        salt = bytes.fromhex(challenge_data['salt'])
        iv = bytes.fromhex(challenge_data['iv'])
        
        encrypted = self._aes256(challenge, self.password, salt, iv)

        r = requests.post(
            f"{self.host}/verify-challenge",
            headers={
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "1"
            },
            json={"response": encrypted},
        )

        if not r.ok:
            raise Exception("Failed to verify challenge")

        if r.json()['success'] == "true":
            self.challenge_response = encrypted
            return True
        
        return False

    def get_tasks(self):
        """Get list of available tasks"""
        
        if not self.challenge_response:
            raise Exception("Not authenticated - call login() first")
            
        r = requests.post(
            f"{self.host}/get-active-tasks",
            headers={
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "1"
            },
            json={"response": self.challenge_response},
        )
        if not r.ok:
            raise Exception("Failed to get tasks")
        
        return r.json()

    def buy_token(self, task_uuid, token_address, amount=0, pool_address="", base_vault="", quote_vault="", is_raydium=False, is_pumpfun=False, is_pumpfun_amm=False):
        """Buy a Pump.Fun, Pump.Fun AMM or Raydium AMM token
        
        Args:
            task_uuid (str): UUID of the task to use
            token_address (str): Address of token to buy
            pool_address (str): Optional RaydiumAmm Id address
            base_vault (str): Optional base vault address
            quote_vault (str): Optional quote vault address
            amount (float): Optional buy amount in SOL, if empty the buy amount set in the task will be used
            is_raydium (bool): Whether to use Raydium or not
            is_pumpfun (bool): Whether to use Pump.Fun or not
            is_pumpfun_amm (bool): Whether to use Pump.Fun AMM or not
        """
        if not self.challenge_response:
            raise Exception("Not authenticated - call login() first")
            
        r = requests.post(
            f"{self.host}/buy-token",
            headers={
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "1"
            },
            json={
                "task_uuid": task_uuid,
                "token_address": token_address,
                "pool_address": pool_address,
                "base_vault": base_vault,
                "quote_vault": quote_vault,
                "is_raydium": is_raydium,
                "is_pumpfun": is_pumpfun,
                "is_pf_amm": is_pumpfun_amm,
                "buy_amount": amount,
                "challenge_response": self.challenge_response
            },
        )
        if not r.ok:
            raise Exception("Failed to buy token")

    def sell_token(self, task_uuid, token_address, percentage):
        """Sell a previously bought token
        
        Args:
            task_uuid (str): UUID of the task to use  
            token_address (str): Address of token to sell
            percentage (float): Percentage of holdings to sell (0-100)
        """
        if not self.challenge_response:
            raise Exception("Not authenticated - call login() first")
            
        r = requests.post(
            f"{self.host}/sell-token",
            headers={
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "1"
            },
            json={
                "task_uuid": task_uuid,
                "token_address": token_address, 
                "sell_percentage": percentage,
                "challenge_response": self.challenge_response
            }
        )
        if not r.ok:
            raise Exception("Failed to sell token")