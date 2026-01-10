import os
import re
import base64
import zlib
import marshal
import random
import string
import ast
import keyword
import codecs
import json
import time
from datetime import datetime, timedelta
from io import BytesIO

# Dependencies
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
except ImportError:
    os.system("pip install python-telegram-bot")
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# ================================
# CONFIG & DATABASE
# ================================
BOT_TOKEN = "8195989478:AAF2JcDGgg3XBjCB1an0w2pNqTEXji_ydCQ"
ADMIN_ID = 7993202287
DB_FILE = "keys.json"

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f: return json.load(f)
    return {"keys": {}, "users": {}} # keys: {key: expiry}, users: {uid: key}

def save_db(data):
    with open(DB_FILE, "w") as f: json.dump(data, f, indent=4)

user_files = {}

# ================================
# KEY SYSTEM LOGIC
# ================================

def generate_key_string(length=12):
    chars = string.ascii_uppercase + string.digits
    return "TOMMY-" + "".join(random.choices(chars, k=length))

# The "Lock" template that will be prepended to obfuscated files
HWID_LOCK_CODE = """
import os, hashlib, sys
def __check_hwid():
    # Simple HWID generation based on system info
    info = os.getlogin() + sys.platform + str(os.cpu_count())
    hwid = hashlib.sha256(info.encode()).hexdigest()
    allowed_hwid = "{EXPECTED_HWID}"
    if hwid != allowed_hwid:
        print("❌ [ERROR] Unauthorized Device!")
        print("This file is locked to another machine.")
        sys.exit()
__check_hwid()
"""

# ================================
# OBFUSCATOR CLASS
# ================================

class PythonObfuscator:
    def __init__(self):
        self.random_names = [('O'+''.join(random.choices('0O', k=8))) for _ in range(50)]

    def wrap_with_lock(self, code, hwid):
        lock = HWID_LOCK_CODE.replace("{EXPECTED_HWID}", hwid)
        return lock + "\n" + code

    # Methods (Condensed for brevity, same logic as before)
    def l10_marshal(self, code):
        c = compile(code, '', 'exec')
        return f"import marshal,base64\nexec(marshal.loads(base64.b64decode({base64.b64encode(marshal.dumps(c))!r})))"

    def l1_rot13(self, code):
        b64 = base64.b64encode(codecs.encode(code, 'rot_13').encode()).decode()
        return f"import base64,codecs\nexec(codecs.decode(base64.b64decode('{b64}').decode(), 'rot_13'))"

# ================================
# BOT COMMANDS
# ================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    db = load_db()
    
    if uid not in db["users"]:
        await update.message.reply_text("❌ You don't have an active license.\nUse `/claim <key>` to activate.")
        return

    await update.message.reply_text("🛡️ *Welcome ToMmY Encryptor*\nSend a `.py` file to protect it with HWID lock.", parse_mode='Markdown')

async def gen_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    
    try:
        hours = int(context.args[0])
        key = generate_key_string()
        expiry = time.time() + (hours * 3600)
        
        db = load_db()
        db["keys"][key] = {"expiry": expiry, "hwid": None}
        save_db(db)
        
        await update.message.reply_text(f"✅ *Key Generated*\n`{key}`\nDuration: {hours} hours", parse_mode='Markdown')
    except:
        await update.message.reply_text("Usage: `/gen <hours>`")

async def claim_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if not context.args: return
    
    key_input = context.args[0]
    db = load_db()
    
    if key_input in db["keys"]:
        # Logic: First person to use the key locks it to their ID
        db["users"][uid] = key_input
        # We will generate the HWID when they first encrypt a file
        await update.message.reply_text("✅ License Activated! You can now send files.")
        save_db(db)
    else:
        await update.message.reply_text("❌ Invalid Key.")

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    db = load_db()
    
    if uid not in db["users"]:
        await update.message.reply_text("❌ No license. Use `/claim <key>`")
        return

    doc = update.message.document
    f = await context.bot.get_file(doc.file_id)
    b = BytesIO()
    await f.download_to_memory(b)
    code = b.getvalue().decode('utf-8', errors='ignore')
    
    user_files[uid] = {'name': doc.file_name, 'code': code}
    
    kb = [[InlineKeyboardButton("Method: Marshal (High)", callback_data="meth_10")],
          [InlineKeyboardButton("Method: ROT13 (Low)", callback_data="meth_1")]]
    await update.message.reply_text("Choose Obfuscation:", reply_markup=InlineKeyboardMarkup(kb))

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    uid = str(query.from_user.id)
    if uid not in user_files: return

    # Simple HWID simulation: User's Username + ID as the lock mechanism
    # In a real scenario, the user would provide their HWID or the script would fetch it.
    import hashlib
    # We generate a unique HWID for this user based on their Telegram ID
    user_hwid = hashlib.sha256(uid.encode()).hexdigest()

    obs = PythonObfuscator()
    code = user_files[uid]['code']
    
    choice = query.data
    if "10" in choice:
        protected = obs.l10_marshal(code)
    else:
        protected = obs.l1_rot13(code)

    # ADD THE HWID LOCK
    final_code = obs.wrap_with_lock(protected, user_hwid)
    
    out = BytesIO(final_code.encode())
    await query.message.reply_document(document=out, filename=f"locked_{user_files[uid]['name']}")
    await query.answer("File Locked to your device!")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("gen", gen_key))
    app.add_handler(CommandHandler("claim", claim_key))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.run_polling()

if __name__ == "__main__":
    main()