#!/usr/bin/env python3
import cv2
import hashlib
import hmac
import os
import ecdsa
import time
import argparse
import logging

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
    time.sleep(2)  # Add 2 second delay to ensure camera initialization is complete
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

def seed_to_master_key(seed: bytes):
    """
    Calculate master private key and chain code according to BIP32 using HMAC_SHA512("Bitcoin seed", seed)
    """
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_private_key = I[:32]
    master_chain_code = I[32:]
    return master_private_key, master_chain_code

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
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, byteorder="big")
    encode = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encode = alphabet[rem] + encode
    # For each leading zero byte, add a '1'
    n_pad = len(b) - len(b.lstrip(b'\x00'))
    return "1" * n_pad + encode

def public_key_to_address(public_key: bytes) -> str:
    """
    Calculate Bitcoin address:
      1. Apply SHA256 to public key, then RIPEMD160
      2. Add version byte 0x00 (mainnet) in front
      3. Calculate double SHA256 checksum and take first 4 bytes
      4. Concatenate and encode with Base58
    """
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    ver_ripemd160 = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(ver_ripemd160).digest()).digest()[:4]
    binary_address = ver_ripemd160 + checksum
    address = base58_encode(binary_address)
    return address

###############################
# Main Program Entry
###############################
def main():
    parser = argparse.ArgumentParser(description="Generate mnemonic using camera frames.")
    parser.add_argument('--list-cameras', action='store_true', help='List all available cameras')
    parser.add_argument('--camera-index', type=int, default=None, help='Specify the camera index to use')
    parser.add_argument('--num-words', type=int, default=12, help='Number of words in the mnemonic')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.list_cameras:
        select_camera()
    else:
        num_words = args.num_words
        logger.info("Starting mnemonic generation using camera...")
        
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
        master_private_key, master_chain_code = seed_to_master_key(seed)
        logger.info("\nMaster private key (hex):")
        logger.info(master_private_key.hex())
        
        # Generate compressed public key and wallet address
        public_key = private_key_to_public_key(master_private_key)
        wallet_address = public_key_to_address(public_key)
        logger.info("\nWallet address:")
        logger.info(wallet_address)

if __name__ == "__main__":
    main()