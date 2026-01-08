import os
import json
from datetime import datetime
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv
import yaml

from static import StaticAnalyzer

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
DOWNLOAD_FOLDER = "downloads"
USERS_FILE = "allowed_users.json"

bot = telebot.TeleBot(BOT_TOKEN)

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

static_analyzer = StaticAnalyzer(config)

try:
    from dynamic import DynamicAnalyzer
    dynamic_analyzer = DynamicAnalyzer(timeout=30, db_path="logs/dynamic_analysis.db")
    DYNAMIC_ENABLED = True
except (ImportError, RuntimeError):
    dynamic_analyzer = None
    DYNAMIC_ENABLED = False

def escape_md(text):
    for c in '_*[]()~`>#+-=|{}.!':
        text = text.replace(c, '\\' + c)
    return text

def load_users():
    if not os.path.exists(USERS_FILE):
        data = {"users": [], "admin": [], "privat_admin": [], "allowed_groups": []}
        save_users(data)
        return data
    with open(USERS_FILE, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return {"users": data, "admin": [], "privat_admin": [], "allowed_groups": []}
    for k in ["users", "admin", "privat_admin", "allowed_groups"]:
        data.setdefault(k, [])
    return data

def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

USER_DATA = load_users()
PRIVATE_ADMINS = USER_DATA["privat_admin"]
ADMINS = USER_DATA["admin"]
ALL_USERS = USER_DATA["users"]
ALLOWED_USERS = list(set(PRIVATE_ADMINS + ADMINS))
ALLOWED_GROUPS = USER_DATA["allowed_groups"]

def is_admin(uid): return uid in PRIVATE_ADMINS
def has_access(uid): return uid in ALLOWED_USERS
def is_group(msg): return msg.chat.type in ['group', 'supergroup']

def get_folder(uid, is_grp=False):
    name = f"group_{abs(uid)}" if is_grp else str(uid)
    folder = os.path.join(DOWNLOAD_FOLDER, name)
    os.makedirs(folder, exist_ok=True)
    return folder

def get_files(folder):
    return sorted([f for f in os.listdir(folder) if not f.startswith(".")])

def main_kb(uid):
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("📂 Мои файлы", callback_data="files"))
    if is_admin(uid):
        kb.row(InlineKeyboardButton("🔒 Админ-панель", callback_data="admin_panel"))
    return kb

def admin_kb():
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("➕ Добавить пользователя", callback_data="add_admin"))
    kb.row(InlineKeyboardButton("👑 Добавить супер-админа", callback_data="add_padmin"))
    kb.row(InlineKeyboardButton("🚫 Заблокировать", callback_data="block"))
    kb.row(InlineKeyboardButton("👥 Добавить группу", callback_data="add_grp"))
    kb.row(InlineKeyboardButton("🗑 Удалить группу", callback_data="del_grp"))
    kb.row(InlineKeyboardButton("📜 Список доступа", callback_data="list"))
    kb.row(InlineKeyboardButton("🔙 Назад", callback_data="back"))
    return kb

def files_kb(uid, is_grp=False):
    kb = InlineKeyboardMarkup()
    folder = get_folder(uid, is_grp)
    files = get_files(folder)
    prefix = "gf:" if is_grp else "f:"
    if not files:
        kb.row(InlineKeyboardButton("Список пуст", callback_data="x"))
    else:
        for i, f in enumerate(files):
            name = f if len(f) < 25 else f[:22] + "..."
            kb.row(InlineKeyboardButton(f"📄 {name}", callback_data=f"{prefix}{i}"))
    kb.row(InlineKeyboardButton("🔙 Назад", callback_data="gback" if is_grp else "back"))
    return kb

def file_kb(idx, is_grp=False):
    kb = InlineKeyboardMarkup()
    prefix = "g" if is_grp else ""
    if DYNAMIC_ENABLED:
        kb.row(InlineKeyboardButton("🔬 Полный анализ", callback_data=f"{prefix}full:{idx}"))
    kb.row(InlineKeyboardButton("🔍 Статический анализ", callback_data=f"{prefix}stat:{idx}"))
    kb.row(InlineKeyboardButton("🗑 Удалить", callback_data=f"{prefix}del:{idx}"))
    kb.row(InlineKeyboardButton("К списку", callback_data="gfiles" if is_grp else "files"))
    return kb

def group_kb():
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("📂 Файлы группы", callback_data="gfiles"))
    return kb

def run_static(path):
    try:
        return static_analyzer.run(path)
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR", "score": 0}

def run_dynamic(path):
    if not DYNAMIC_ENABLED:
        return {"error": "Недоступно"}
    try:
        return dynamic_analyzer.run(path)
    except Exception as e:
        return {"error": str(e)}

def format_report(res, fname, dyn=None):
    v = res.get("verdict", "UNKNOWN")
    s = res.get("score", 0)
    emoji = {"CLEAN": "✅", "SUSPICIOUS": "⚠️", "MALICIOUS": "🚨"}.get(v, "❓")
    
    r = f"{emoji} **Файл:** `{fname}`\n\n**Вердикт:** `{v}`\n**Score:** {s}\n"
    
    if res.get("yara_matches"):
        r += f"\n**YARA:** `{', '.join(res['yara_matches'][:3])}`\n"
    if res.get("clamav", {}).get("infected"):
        r += f"**ClamAV:** `{res['clamav']['signature']}`\n"
    if res.get("hash"):
        r += f"\n**SHA256:** `{res['hash']}`\n"
    
    if dyn and not dyn.get("error"):
        r += f"\n**🔬 Динамика:**\nВердикт: `{dyn['verdict']}`\n"
        r += f"Threat: {dyn['threat_score']}\nДлительность: {dyn['duration']:.2f}s\n"
        if dyn.get('reasons'):
            r += "Причины:\n" + "\n".join(f"• {x}" for x in dyn['reasons'][:3]) + "\n"
        final = s + dyn['threat_score']
        fv = "🚨 MALICIOUS" if final >= 70 else "⚠️ SUSPICIOUS" if final >= 40 else "✅ CLEAN"
        r += f"\n**Итог:** {fv} (score: {final})"
    return r

def extract_file(msg):
    if msg.document:
        return msg.document.file_id, msg.document.file_name
    if msg.photo:
        return msg.photo[-1].file_id, f"photo_{msg.photo[-1].file_unique_id}.jpg"
    if msg.video:
        return msg.video.file_id, msg.video.file_name or f"video_{msg.video.file_unique_id}.mp4"
    if msg.audio:
        return msg.audio.file_id, msg.audio.file_name or f"audio_{msg.audio.file_unique_id}.mp3"
    if msg.voice:
        return msg.voice.file_id, f"voice_{msg.voice.file_unique_id}.ogg"
    return None, None

def admin_action(msg, action):
    try:
        val = int(msg.text.strip())
    except ValueError:
        bot.send_message(msg.chat.id, "❌ Нужно число")
        return show_main(msg)
    
    if action == "add_admin":
        if val not in ADMINS:
            USER_DATA["admin"].append(val)
            ADMINS.append(val)
            ALLOWED_USERS.append(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"✅ Добавлен: `{val}`", parse_mode="Markdown")
        else:
            bot.send_message(msg.chat.id, "Уже есть")
    
    elif action == "add_padmin":
        if val not in PRIVATE_ADMINS:
            USER_DATA["privat_admin"].append(val)
            PRIVATE_ADMINS.append(val)
            if val not in ALLOWED_USERS:
                ALLOWED_USERS.append(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"👑 Супер-админ: `{val}`", parse_mode="Markdown")
        else:
            bot.send_message(msg.chat.id, "Уже есть")
    
    elif action == "block":
        if val in PRIVATE_ADMINS:
            bot.send_message(msg.chat.id, "Нельзя заблокировать супер-админа")
        elif val in ALLOWED_USERS:
            if val in USER_DATA["admin"]:
                USER_DATA["admin"].remove(val)
                ADMINS.remove(val)
            ALLOWED_USERS.remove(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"🚫 Заблокирован: `{val}`", parse_mode="Markdown")
        else:
            bot.send_message(msg.chat.id, "Не найден")
    
    elif action == "add_grp":
        if val >= 0:
            bot.send_message(msg.chat.id, "ID группы должен быть отрицательным")
        elif val in ALLOWED_GROUPS:
            bot.send_message(msg.chat.id, "Уже добавлена")
        else:
            USER_DATA["allowed_groups"].append(val)
            ALLOWED_GROUPS.append(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"✅ Группа: `{val}`", parse_mode="Markdown")
    
    elif action == "del_grp":
        if val in ALLOWED_GROUPS:
            USER_DATA["allowed_groups"].remove(val)
            ALLOWED_GROUPS.remove(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"🗑 Удалена: `{val}`", parse_mode="Markdown")
        else:
            bot.send_message(msg.chat.id, "Не найдена")
    
    show_main(msg)

def show_main(msg):
    uid = msg.from_user.id
    bot.send_message(msg.chat.id, "**Malware Inspector for Telegram**\n\nОтправьте файл для анализа",
                     reply_markup=main_kb(uid), parse_mode="Markdown")

@bot.message_handler(commands=["start"])
def cmd_start(msg):
    uid, cid = msg.from_user.id, msg.chat.id
    
    if is_group(msg):
        if cid not in ALLOWED_GROUPS:
            bot.reply_to(msg, "❌ Группа не авторизована")
            return
        bot.send_message(cid, "**Malware Inspector for Telegram**\n\nОтправьте файл для анализа",
                         reply_markup=group_kb(), parse_mode="Markdown")
        return
    
    if uid not in ALL_USERS:
        USER_DATA["users"].append(uid)
        ALL_USERS.append(uid)
        save_users(USER_DATA)
    
    if has_access(uid):
        bot.send_message(uid, "**Malware Inspector for Telegram**\n\nОтправьте файл для проверки",
                         reply_markup=main_kb(uid), parse_mode="Markdown")
    else:
        bot.send_message(uid, "Нет доступа")

@bot.message_handler(commands=["myid"])
def cmd_myid(msg):
    bot.reply_to(msg, f"Ваш ID: `{msg.from_user.id}`", parse_mode="Markdown")

@bot.message_handler(commands=["groupid"])
def cmd_gid(msg):
    if not is_admin(msg.from_user.id):
        return
    cid = msg.chat.id
    status = "✅" if cid in ALLOWED_GROUPS else "❌"
    bot.reply_to(msg, f"**ID:** `{cid}`\n**Статус:** {status}", parse_mode="Markdown")

@bot.message_handler(commands=["admin"])
def cmd_admin(msg):
    uid = msg.from_user.id
    if not is_admin(uid):
        bot.reply_to(msg, "❌ Только для супер-админов")
        return
    text = f"🔒 **Админ-панель**\n\n👑 {len(PRIVATE_ADMINS)} | 👤 {len(ADMINS)} | 👥 {len(ALLOWED_GROUPS)}"
    bot.send_message(msg.chat.id, text, reply_markup=admin_kb(), parse_mode="Markdown")

@bot.message_handler(content_types=["document", "photo", "video", "audio", "voice"])
def handle_file(msg):
    uid, cid = msg.from_user.id, msg.chat.id
    is_grp = is_group(msg)
    
    if is_grp:
        if cid not in ALLOWED_GROUPS:
            return
        folder = get_folder(cid, True)
    else:
        if not has_access(uid):
            return
        folder = get_folder(uid)
    
    file_id, fname = extract_file(msg)
    if not file_id:
        return
    
    try:
        status = bot.reply_to(msg, "⏳ Анализ...")
        info = bot.get_file(file_id)
        data = bot.download_file(info.file_path)
        path = os.path.join(folder, fname)
        
        with open(path, "wb") as f:
            f.write(data)
        
        res = run_static(path)
        v, s = res.get("verdict", "UNKNOWN"), res.get("score", 0)
        emoji = {"CLEAN": "✅", "SUSPICIOUS": "⚠️", "MALICIOUS": "🚨"}.get(v, "❓")
        
        report = f"{emoji} **{escape_md(fname)}**\n\nВердикт: `{v}` | Score: {s}\n"
        if res.get("yara_matches"):
            report += f"YARA: {escape_md(', '.join(res['yara_matches'][:2]))}\n"
        if res.get("clamav", {}).get("infected"):
            report += f"ClamAV: {escape_md(res['clamav']['signature'])}\n"
        
        files = get_files(folder)
        idx = files.index(fname) if fname in files else 0
        
        bot.edit_message_text(report, cid, status.message_id, 
                              parse_mode="Markdown", reply_markup=file_kb(idx, is_grp))
    except Exception as e:
        bot.reply_to(msg, f"❌ Ошибка: {e}")

@bot.callback_query_handler(func=lambda c: True)
def on_cb(call):
    uid, cid = call.from_user.id, call.message.chat.id
    d = call.data
    
    if uid not in ALL_USERS:
        USER_DATA["users"].append(uid)
        ALL_USERS.append(uid)
        save_users(USER_DATA)
    
    if not has_access(uid) and d not in ["gfiles", "gback", "x"] and not d.startswith("g"):
        bot.answer_callback_query(call.id, "Нет доступа")
        return
    
    is_grp = d.startswith("g") and d not in ["grp"]
    folder_id = cid if is_grp else uid
    
    if d == "back":
        bot.edit_message_text("**Malware Inspector for Telegram**", cid, call.message.message_id,
                              reply_markup=main_kb(uid), parse_mode="Markdown")
    
    elif d == "gback":
        bot.edit_message_text("**Malware Inspector for Telegram**", cid, call.message.message_id,
                              reply_markup=group_kb(), parse_mode="Markdown")
    
    elif d == "files":
        bot.edit_message_text("📂 **Ваши файлы:**", cid, call.message.message_id,
                              reply_markup=files_kb(uid), parse_mode="Markdown")
    
    elif d == "gfiles":
        bot.edit_message_text("📂 **Файлы группы:**", cid, call.message.message_id,
                              reply_markup=files_kb(cid, True), parse_mode="Markdown")
    
    elif d.startswith("f:") or d.startswith("gf:"):
        is_grp = d.startswith("gf:")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if is_grp else uid, is_grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Не найден")
            return
        fname = files[idx]
        path = os.path.join(folder, fname)
        if os.path.exists(path):
            sz = f"{os.path.getsize(path) / 1024 / 1024:.2f} MB"
            dt = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%d.%m.%Y %H:%M")
        else:
            sz, dt = "?", "?"
        bot.edit_message_text(f"**Файл:** `{fname}`\n**Размер:** {sz}\n**Дата:** {dt}",
                              cid, call.message.message_id, reply_markup=file_kb(idx, is_grp),
                              parse_mode="Markdown")
    
    elif d.startswith("stat:") or d.startswith("gstat:"):
        is_grp = d.startswith("g")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if is_grp else uid, is_grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Не найден")
            return
        fname = files[idx]
        path = os.path.join(folder, fname)
        bot.edit_message_text(f"🔍 Анализ `{fname}`...", cid, call.message.message_id,
                              parse_mode="Markdown")
        res = run_static(path)
        bot.edit_message_text(format_report(res, fname), cid, call.message.message_id,
                              reply_markup=file_kb(idx, is_grp), parse_mode="Markdown")
    
    elif d.startswith("full:") or d.startswith("gfull:"):
        is_grp = d.startswith("g")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if is_grp else uid, is_grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Не найден")
            return
        fname = files[idx]
        path = os.path.join(folder, fname)
        if not DYNAMIC_ENABLED:
            bot.answer_callback_query(call.id, "Динамика недоступна")
            return
        bot.edit_message_text(f"🔬 Полный анализ `{fname}`...", cid, call.message.message_id,
                              parse_mode="Markdown")
        res = run_static(path)
        dyn = run_dynamic(path)
        bot.edit_message_text(format_report(res, fname, dyn), cid, call.message.message_id,
                              reply_markup=file_kb(idx, is_grp), parse_mode="Markdown")
    
    elif d.startswith("del:") or d.startswith("gdel:"):
        is_grp = d.startswith("g")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if is_grp else uid, is_grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Не найден")
            return
        fname = files[idx]
        path = os.path.join(folder, fname)
        if os.path.exists(path):
            os.remove(path)
        bot.answer_callback_query(call.id, f"🗑 {fname}")
        bot.edit_message_text("📂 **Файлы:**", cid, call.message.message_id,
                              reply_markup=files_kb(cid if is_grp else uid, is_grp),
                              parse_mode="Markdown")
    
    elif d == "admin_panel":
        if not is_admin(uid):
            bot.answer_callback_query(call.id, "Нет доступа")
            return
        text = f"🔒 **Админ-панель**\n\n👑 {len(PRIVATE_ADMINS)} | 👤 {len(ADMINS)} | 👥 {len(ALLOWED_GROUPS)}"
        bot.edit_message_text(text, cid, call.message.message_id,
                              reply_markup=admin_kb(), parse_mode="Markdown")
    
    elif d == "list":
        if not is_admin(uid):
            return
        t = f"**👑 Супер-админы:** {PRIVATE_ADMINS[:5]}\n"
        t += f"**👤 Админы:** {ADMINS[:5]}\n"
        t += f"**👥 Группы:** {ALLOWED_GROUPS[:5]}"
        bot.edit_message_text(t, cid, call.message.message_id,
                              reply_markup=admin_kb(), parse_mode="Markdown")
    
    elif d in ["add_admin", "add_padmin", "block", "add_grp", "del_grp"]:
        if not is_admin(uid):
            bot.answer_callback_query(call.id, "Нет доступа")
            return
        prompts = {
            "add_admin": "ID пользователя:",
            "add_padmin": "ID супер-админа:",
            "block": "ID для блокировки:",
            "add_grp": "ID группы (отрицательное):",
            "del_grp": "ID группы для удаления:"
        }
        m = bot.send_message(cid, prompts[d])
        bot.register_next_step_handler(m, lambda msg: admin_action(msg, d))
    
    elif d == "x":
        bot.answer_callback_query(call.id)

if __name__ == "__main__":
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    print("Bot started")
    bot.infinity_polling()
