# Wallet Tools Telegram Bot

A **Solana wallet utility bot** built with Python and [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot). Manage, analyze, and convert wallet data directly from Telegram.

**Supports**  
- Mnemonic → Address conversion  
- SOL / SPL token balance checks  
- Phrase extraction by address  
- Duplicate removal and dataset cleaning  

> **Security First:** This bot **never stores mnemonics** unless you explicitly enable it via `SAVE_MNEMONICS=true`.

---

## Features

| Command               | Description                                           |
|-----------------------|-------------------------------------------------------|
| `/generate_addresses` | Convert mnemonic phrases to Solana addresses          |
| `/check_balances`     | Check SOL or any SPL token balances                   |
| `/extract_phrases`    | Find which mnemonic in a wordlist matches an address  |
| `/remove_common`      | Remove phrases from List A that exist in List B       |
| `/deduplicate`        | Remove duplicate lines from any list/wordlist         |

---

## Requirements

- Python 3.9+  
- Telegram Bot Token [](https://t.me/BotFather)  
- Internet connection (Solana RPC)

---

## Installation & Setup

```bash
git clone https://github.com/yourusername/wallet-tools-bot.git
cd wallet-tools-bot

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

export TELEGRAM_BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
export SAVE_MNEMONICS="false"          # Set "true" only if you want to log hits
export SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"  # Optional custom RPC

python3 wallet_tools_bot.py
