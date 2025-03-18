# WalletGen - Generate Wallet with Movements

[English](README.md) | [中文](README.zh_cn.md)

The most joyful wallet generator - start dancing in front of your camera!

## How It Works

1. The program accesses your camera
2. Captures a frame for each mnemonic word
3. Hashes each frame to generate random numbers
4. Uses these random numbers to select words from the BIP39 wordlist
5. Derives the seed and master private key from the mnemonic according to BIP39/BIP32 standards
6. Generates the corresponding wallet address

## Features

- Uses physical input as an entropy source
- Fully compliant with BIP39 and BIP32 standards
- Supports 12-word mnemonics (customizable length)
- Generates standard wallet addresses
- Option to select specific cameras (if multiple are available)
- Supports multiple cryptocurrency wallet types: Bitcoin (BTC), Ethereum (ETH), and Tron (TRC)

## Usage

Basic usage:
```
python main.py
```

List available cameras:
```
python main.py --list-cameras
```

Specify camera and mnemonic length:
```
python main.py --camera-index 1 --num-words 24
```

Generate different wallet types:
```
python main.py --coin-type BTC  # Default: Bitcoin
python main.py --coin-type ETH  # Ethereum
python main.py --coin-type TRC  # Tron
```

View more options:
```
python main.py --help
```

## Technical Details

- Uses OpenCV to access the camera
- Employs SHA-256 for hash calculations
- Generates mnemonics based on BIP39 standard
- Derives master keys following BIP32 specifications
- Supports various wallet formats (BTC/ETH/TRC)
- Complies with cryptocurrency address generation standards

## Dependencies

- Python 3 <= 3.10
- opencv-python
- ecdsa
- pysha3

## License

This project is licensed under the MIT License - see the LICENSE file for details 