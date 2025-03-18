#!/usr/bin/env python3
import cv2
import hashlib
import hmac
import os
import ecdsa
import time
import argparse
import logging
import binascii
import struct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

###############################
# Load BIP39 English Word List
###############################
def load_bip39_wordlist(filepath="bip39_english.txt"):
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            "BIP39 word list file bip39_english.txt not found. Please download and place it in the same directory.")
    with open(filepath, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise ValueError("BIP39 word list must contain 2048 words")
    return words

###############################
# Capture Frames from Camera
###############################
def select_camera():
    """
    List all available cameras and return their index
    """
    available_cameras = []
    index = 0
    while True:
        cap = cv2.VideoCapture(index)
        if not cap.isOpened():
            break
        ret, _ = cap.read()
        if ret:
            backend = cap.getBackendName()
            name = "Unknown"
            try:
                name = cap.getBackendName()
            except:
                pass
            logger.info(f"Found camera {index}: Backend={backend}, Name={name}")
            available_cameras.append((index, name, backend))
        cap.release()
        index += 1
    
    if not available_cameras:
        logger.warning("No available cameras found.")
    else:
        logger.info("Available cameras:")
        for cam in available_cameras:
            logger.info(f"Index: {cam[0]}, Name: {cam[1]}, Backend: {cam[2]}")
    
    return available_cameras[0][0]

def capture_frame(cap):
    """
    Capture a frame from an open camera
    """
    time.sleep(0.5)  # Add 0.5 second delay to ensure camera initialization is complete
    ret, frame = cap.read()
    if not ret:
        raise Exception("Failed to capture camera frame")
    return frame.tobytes()

###############################
# Simple SHA256-based DRBG Implementation
###############################
def drbg(seed: bytes):
    counter = 0
    while True:
        data = seed + counter.to_bytes(4, byteorder="big")
        hash_out = hashlib.sha256(data).digest()
        for b in hash_out:
            yield b
        counter += 1

def randbelow(n: int, drbg_gen) -> int:
    """
    Use rejection sampling to generate an integer in range [0, n) from drbg_gen.
    """
    num_bytes = (n.bit_length() + 7) // 8
    while True:
        random_bytes = bytes([next(drbg_gen) for _ in range(num_bytes)])
        r = int.from_bytes(random_bytes, byteorder="big")
        # Rejection sampling ensures uniformity
        if r < (1 << (num_bytes * 8)) - ((1 << (num_bytes * 8)) % n):
            return r % n

###############################
# Generate Mnemonic Using Camera Frame Hashes
###############################
def generate_mnemonic(cap, num_words=12):
    wordlist = load_bip39_wordlist()  # 2048 words
    mnemonic = []
    logger.info("Ensure the camera is focused and ready (a frame will be captured for each word)")
    time.sleep(2)
    for i in range(num_words):
        # Capture a frame and compute its hash
        frame_bytes = capture_frame(cap)
        frame_hash = hashlib.sha256(frame_bytes).digest()
        # Use frame hash to construct DRBG
        drbg_gen = drbg(frame_hash)
        # Use DRBG to randomly select an index in range [0, 2048)
        idx = randbelow(2048, drbg_gen)
        selected_word = wordlist[idx]
        mnemonic.append(selected_word)
        logger.info(f"Word {i+1}: {selected_word}")

    return mnemonic

###############################
# Calculate Seed, Master Private Key and Wallet Address from Mnemonic
###############################
def mnemonic_to_seed(mnemonic, passphrase=""):
    """
    Calculate seed according to BIP39 using PBKDF2_HMAC_SHA512
    """
    mnemonic_sentence = " ".join(mnemonic)
    salt = "mnemonic" + passphrase
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic_sentence.encode("utf-8"),
                               salt.encode("utf-8"), 2048)
    return seed

def derive_bip32_path(seed, coin_type="BTC", account=0, change=0, address_index=0):
    """
    Derive private key following BIP32/BIP44 path
    Different coins have different paths:
    BTC: m/44'/0'/account'/change/address_index
    ETH: m/44'/60'/account'/change/address_index
    TRC: m/44'/195'/account'/change  (Tron uses 4-level path)
    """
    # Set derivation path based on coin type
    if coin_type == "BTC":
        path = f"m/44'/0'/{account}'/0/{address_index}"
        coin_code = 0
        use_five_levels = True
    elif coin_type == "ETH":
        path = f"m/44'/60'/{account}'/0/{address_index}"
        coin_code = 60
        use_five_levels = True
    elif coin_type == "TRC":
        path = f"m/44'/195'/{account}'/0"  # Tron uses 4 levels
        coin_code = 195
        use_five_levels = False
    else:
        raise ValueError(f"Unsupported coin type: {coin_type}")
        
    logger.info(f"Using derivation path: {path}")
    
    # BIP32 derivation
    # Master key generation
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_private_key, master_chain_code = I[:32], I[32:]
    
    # Purpose level: 44' (hardened)
    key = master_private_key
    data = b'\x00' + key + struct.pack('>I', 0x8000002C)  # 44' hardened
    I = hmac.new(master_chain_code, data, hashlib.sha512).digest()
    key, chain_code = I[:32], I[32:]
    
    # Coin type level: coin_code' (hardened)
    data = b'\x00' + key + struct.pack('>I', 0x80000000 + coin_code)  # coin' hardened
    I = hmac.new(chain_code, data, hashlib.sha512).digest()
    key, chain_code = I[:32], I[32:]
    
    # Account level: account' (hardened)
    data = b'\x00' + key + struct.pack('>I', 0x80000000 + account)  # account' hardened
    I = hmac.new(chain_code, data, hashlib.sha512).digest()
    key, chain_code = I[:32], I[32:]
    
    # Change level: change (not hardened)
    public_key = private_key_to_public_key(key)
    data = public_key + struct.pack('>I', change)  # change not hardened
    I = hmac.new(chain_code, data, hashlib.sha512).digest()
    key, chain_code = I[:32], I[32:]
    
    # For 5-level paths (BTC and ETH), add the address_index level
    if use_five_levels:
        # Address index level: address_index (not hardened)
        public_key = private_key_to_public_key(key)
        data = public_key + struct.pack('>I', address_index)  # address_index not hardened
        I = hmac.new(chain_code, data, hashlib.sha512).digest()
        key, chain_code = I[:32], I[32:]
    
    return key, chain_code, path

def seed_to_master_key(seed: bytes, coin_type="BTC"):
    """
    Calculate master private key and chain code according to BIP32 using HMAC_SHA512("Bitcoin seed", seed)
    """
    derived_private_key, derived_chain_code, path = derive_bip32_path(seed, coin_type)
    return derived_private_key, derived_chain_code

def private_key_to_public_key(private_key: bytes) -> bytes:
    """
    Generate compressed public key using ecdsa library
    """
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    # Get x, y coordinates
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, byteorder="big")
    # Compressed public key: prefix is 0x02 if y is even, otherwise 0x03
    prefix = b'\x02' if (y % 2 == 0) else b'\x03'
    return prefix + x_bytes

def base58_encode(b: bytes) -> str:
    """
    Base58 encode function for Bitcoin and Tron addresses
    """
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, byteorder="big")
    encode = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encode = alphabet[rem] + encode
    # For each leading zero byte, add a '1'
    n_pad = len(b) - len(b.lstrip(b'\x00'))
    return "1" * n_pad + encode

def keccak256(data):
    """
    A better approximation of Keccak-256 hash
    For ETH and TRC address generation
    """
    try:
        # Try to use pysha3 if available
        import sha3
        keccak = sha3.keccak_256()
        keccak.update(data)
        return keccak.digest()
    except ImportError:
        # Fallback to a double-sha256 (not the same as Keccak-256, but better than nothing)
        logger.warning("pysha3 not available, using fallback hashing method for TRC and ETH addresses.")
        logger.warning("For accurate addresses, install pysha3: pip install pysha3")
        hash1 = hashlib.sha256(data).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return hash2

def private_key_to_uncompressed_public_key(private_key: bytes) -> bytes:
    """
    Generate uncompressed public key using ecdsa library
    """
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    # Get x, y coordinates
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    # Uncompressed public key: prefix is 0x04 followed by x and y coordinates
    return b'\x04' + x.to_bytes(32, byteorder="big") + y.to_bytes(32, byteorder="big")

def public_key_to_address(public_key: bytes, coin_type="BTC") -> str:
    """
    Calculate wallet address based on coin type:
    BTC: Bitcoin address format
    ETH: Ethereum address format
    TRC: Tron address format
    """
    if coin_type == "BTC":
        # Bitcoin address format
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
        ver_ripemd160 = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(ver_ripemd160).digest()).digest()[:4]
        binary_address = ver_ripemd160 + checksum
        address = base58_encode(binary_address)
        return address
    
    elif coin_type in ["ETH", "TRC"]:
        # For ETH and TRC we need uncompressed public key
        if len(public_key) == 33:  # compressed key, convert to uncompressed
            # 解析压缩格式的公钥
            prefix = public_key[0]
            x_bytes = public_key[1:33]
            x = int.from_bytes(x_bytes, byteorder="big")
            
            # 使用secp256k1曲线参数
            # y² = x³ + 7 (曲线方程)
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            a = 0
            b = 7
            
            # 计算y²
            y_squared = (pow(x, 3, p) + b) % p
            
            # 计算y，使用Tonelli-Shanks算法求模平方根
            # 简化实现，直接使用pow函数的模逆运算
            y = pow(y_squared, (p + 1) // 4, p)
            
            # 根据压缩公钥的前缀确定y的奇偶性
            if (prefix == 0x02 and y % 2 != 0) or (prefix == 0x03 and y % 2 == 0):
                y = p - y
                
            # 创建非压缩格式的公钥
            uncompressed_pubkey = b'\x04' + x_bytes + y.to_bytes(32, byteorder="big")
        else:
            uncompressed_pubkey = public_key
            
        # Skip the first byte (0x04) when hashing to align with Ethereum and Tron addresses
        pubkey_without_prefix = uncompressed_pubkey[1:]
        
        # Get Keccak-256 hash
        hash_digest = keccak256(pubkey_without_prefix)
        
        if coin_type == "ETH":
            # Ethereum address format
            address = "0x" + binascii.hexlify(hash_digest[-20:]).decode('utf-8')
            return address
        else:  # TRC
            # Tron address format
            tron_prefix = b'\x41'  # Tron address prefix (0x41)
            address_bytes = tron_prefix + hash_digest[-20:]
            checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
            binary_address = address_bytes + checksum
            address = base58_encode(binary_address)
            return address
    
    else:
        raise ValueError(f"Unsupported coin type: {coin_type}. Use BTC, ETH, or TRC.")

###############################
# Main Program Entry
###############################
def main():
    parser = argparse.ArgumentParser(description="Generate mnemonic using camera frames.")
    parser.add_argument('--list-cameras', action='store_true', help='List all available cameras')
    parser.add_argument('--camera-index', type=int, default=None, help='Specify the camera index to use')
    parser.add_argument('--num-words', type=int, default=12, help='Number of words in the mnemonic (12 or 24)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--coin-type', type=str, choices=['BTC', 'ETH', 'TRC'], default='BTC', 
                       help='Specify wallet type: BTC (Bitcoin), ETH (Ethereum), or TRC (Tron)')
    parser.add_argument('--account', type=int, default=0, help='Account index for derivation path')
    parser.add_argument('--address-index', type=int, default=0, help='Address index for derivation path')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.list_cameras:
        select_camera()
    else:
        num_words = args.num_words
        if num_words not in [12, 24]:
            logger.warning(f"Unusual mnemonic length: {num_words}. Standard lengths are 12 or 24 words.")
            
        coin_type = args.coin_type
        logger.info(f"Starting mnemonic generation using camera for {coin_type} wallet...")
        
        # Select camera
        if args.camera_index is not None:
            camera_index = args.camera_index
        else:
            camera_index = select_camera()
        
        cap = cv2.VideoCapture(camera_index)
        if not cap.isOpened():
            raise Exception(f"Cannot open camera {camera_index}")

        try:
            mnemonic = generate_mnemonic(cap, num_words)
        finally:
            cap.release()
            logger.info("Camera closed.")

        mnemonic_sentence = " ".join(mnemonic)
        logger.info("\nGenerated mnemonic:")
        logger.info(mnemonic_sentence)
        
        # Generate seed and master private key
        seed = mnemonic_to_seed(mnemonic)
        
        # Get derived key based on full path
        private_key, chain_code, path = derive_bip32_path(
            seed, 
            coin_type=coin_type, 
            account=args.account, 
            address_index=args.address_index
        )
        
        logger.info("\nPrivate key (hex):")
        logger.info(private_key.hex())
        
        # Generate public key and wallet address
        if coin_type in ["ETH", "TRC"]:
            # For ETH and TRC, use uncompressed public key
            public_key = private_key_to_uncompressed_public_key(private_key)
            logger.info("\nUncompressed public key (hex):")
            logger.info(public_key.hex())
        else:
            # For BTC, use compressed public key
            public_key = private_key_to_public_key(private_key)
            logger.info("\nCompressed public key (hex):")
            logger.info(public_key.hex())
            
        wallet_address = public_key_to_address(public_key, coin_type)
        
        logger.info(f"\n{coin_type} wallet address:")
        logger.info(wallet_address)
        logger.info(f"Derivation path: {path}")

if __name__ == "__main__":
    main()