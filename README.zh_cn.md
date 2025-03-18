# WalletGen - 动作生成钱包

[English](README.md) | [中文](README.zh_cn.md)

最快乐的钱包生成工具，这就开始手舞足蹈。

## 工作原理

1. 程序访问您的摄像头
2. 为每个助记词单词捕获一帧画面
3. 对每一帧进行哈希处理，生成随机数
4. 使用这些随机数从 BIP39 词表中选择单词
5. 根据 BIP39/BIP32 标准，从助记词派生种子和主私钥
6. 生成相应的钱包地址

## 特点

- 使用物理输入作为熵源
- 完全遵循 BIP39 和 BIP32 标准
- 支持 12 词助记词（可自定义长度）
- 生成标准钱包地址
- 可以选择使用特定的摄像头（如果有多个）
- 支持多种加密货币钱包类型：比特币 (BTC)、以太坊 (ETH) 和波场 (TRC)

## 使用方法

基本用法：
```
python main.py
```

列出可用摄像头：
```
python main.py --list-cameras
```

指定摄像头和助记词长度：
```
python main.py --camera-index 1 --num-words 24
```

生成不同类型的钱包：
```
python main.py --coin-type BTC  # 默认：比特币
python main.py --coin-type ETH  # 以太坊
python main.py --coin-type TRC  # 波场
```

查看更多选项：
```
python main.py --help
```

## 技术详情

- 使用 OpenCV 访问摄像头
- 采用 SHA-256 进行哈希计算
- 基于 BIP39 标准生成助记词
- 遵循 BIP32 规范派生主密钥
- 支持多种钱包格式 (BTC/ETH/TRC)
- 符合各种加密货币地址生成标准

## 依赖项

- Python 3 <= 3.10
- opencv-python
- ecdsa
- pysha3

## 许可证

该项目采用 MIT 许可证 - 详情请参阅 LICENSE 文件 