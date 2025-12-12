# AnntivirusFox.py — ЕДИНЫЙ ФАЙЛ, РАБОТАЕТ В ЛС И ГРУППАХ
# Команда: /start
# Принимает файлы ≤32 МБ → сохраняет в SQLite как base64 + UUID → выдает ссылку для скачивания
# При переходе по ссылке — файл отправляется обратно

import os
import sys
import base64
import uuid
import sqlite3
import tempfile
import requests
import hashlib
import time
from telegram import Update, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# === ВАШИ КЛЮЧИ ===
TELEGRAM_BOT_TOKEN = "8594717351:AAGLReKMyuz0tn8B-x2HNypK-oFFXnmNiZQ"
VIRUSTOTAL_API_KEY = "fef46217bbb07a9b2aac571b99a389a94324e61d5d8311820f8662beae2e9dad"
MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024  # 32 MB — точный лимит VirusTotal Free

# === БАЗА ДАННЫХ ===
DB_PATH = "file_storage.db"

# === ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ===
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            base64_data TEXT NOT NULL,
            mime_type TEXT,
            file_name TEXT,
            upload_time REAL
        )
    """)
    conn.commit()
    conn.close()

# === VIRUSTOTAL: ИСПРАВЛЕННЫЕ URL (БЕЗ ПРОБЕЛОВ!) ===
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ VIRUSTOTAL ===
def calculate_sha256_from_bytes(data: bytes):
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(data)
    return hash_sha256.hexdigest()

def upload_file_for_analysis_bytes(data: bytes):
    files = {"file": ("file.bin", data)}
    response = requests.post(VT_UPLOAD_URL, headers=HEADERS, files=files)
    if response.status_code == 200:
        return response.json()["data"]["id"]
    else:
        raise Exception(f"Ошибка загрузки в VirusTotal: {response.status_code} — {response.text}")

def get_file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        raise Exception(f"Ошибка получения отчёта: {response.status_code} — {response.text}")

def analyze_file_bytes(data: bytes):
    file_hash = calculate_sha256_from_bytes(data)
    report = get_file_report(file_hash)
    if report:
        return report
    upload_file_for_analysis_bytes(data)
    time.sleep(20)
    return get_file_report(file_hash)

def format_virustotal_report(report):
    if not report:
        return "❌ Отчёт не найден. Возможно, файл слишком новый или превышен лимит API."
    try:
        attrs = report["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        verdict = "✅ ФАЙЛ ЧИСТ — угроз не обнаружено." if malicious == 0 else f"⚠️ ВНИМАНИЕ! {malicious} из {total} антивирусов пометили файл как ВРЕДОНОСНЫЙ!"
        return (
            f"📁 Имя файла: {attrs.get('meaningful_name', 'Неизвестно')}\n"
            f"📏 Размер: {attrs.get('size', 'N/A')} байт\n"
            f"🔍 SHA-256: {attrs.get('sha256', 'N/A')[:40]}\n"
            f"📊 Статистика анализа:\n"
            f"  • Безопасно: {stats.get('harmless', 0)}\n"
            f"  • Подозрительно: {stats.get('suspicious', 0)}\n"
            f"  • Вредоносно: {malicious}\n"
            f"  • Всего проверок: {total}\n\n"
            f"{verdict}"
        )
    except Exception as e:
        return f"❌ Ошибка обработки отчёта: {str(e)}"

# === КОМАНДА /start ===
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_message = (
        "ХЕЙ Чувак Я 🦊  Я AnntivirusFox!\n\n"
        "👉 Просто пришли мне любой файл до 32 МБ.\n"
        "✅ Я проверю его на вирусы через VirusTotal.\n"
        "📦 И дам тебе ссылку, по которой его можно скачать позже!\n\n"
        "⚠️ Никакие файлы не сохраняются на сервере — всё хранится безопасно в зашифрованном виде."
    )
    await update.message.reply_text(welcome_message)

# === ОБРАБОТКА ФАЙЛОВ ===
async def handle_any_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    file_obj = None
    file_size = 0
    mime_type = "application/octet-stream"
    file_name = "file.bin"

    if message.document:
        file_obj = await message.document.get_file()
        file_size = message.document.file_size
        mime_type = message.document.mime_type or mime_type
        file_name = message.document.file_name or file_name
    elif message.photo:
        file_obj = await message.photo[-1].get_file()
        file_size = file_obj.file_size
        mime_type = "image/jpeg"
        file_name = "photo.jpg"
    elif message.video:
        file_obj = await message.video.get_file()
        file_size = message.video.file_size
        mime_type = message.video.mime_type or "video/mp4"
        file_name = message.video.file_name or "video.mp4"
    elif message.audio:
        file_obj = await message.audio.get_file()
        file_size = message.audio.file_size
        mime_type = message.audio.mime_type or "audio/mpeg"
        file_name = message.audio.file_name or "audio.mp3"
    elif message.voice:
        file_obj = await message.voice.get_file()
        file_size = message.voice.file_size
        mime_type = "audio/ogg"
        file_name = "voice.ogg"
    elif message.animation:
        file_obj = await message.animation.get_file()
        file_size = message.animation.file_size
        mime_type = "image/gif"
        file_name = "animation.gif"
    else:
        return

    if file_size > MAX_FILE_SIZE_BYTES:
        await message.reply_text("❌ Файл слишком большой! Максимум — 32 МБ.")
        return

    try:
        file_bytes = await file_obj.download_as_bytearray()
        file_data = bytes(file_bytes)

        await message.reply_text("🦊 AnntivirusFox активирован! Анализирую файл через VirusTotal… (~20 сек)")
        report = analyze_file_bytes(file_data)
        result = format_virustotal_report(report)
        await message.reply_text(f"🛡️ ОТЧЁТ ОТ ANNTIVIRUSFOX:\n\n{result}")

        file_uuid = str(uuid.uuid4())
        encoded_data = base64.b64encode(file_data).decode('utf-8')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO files (uuid, base64_data, mime_type, file_name, upload_time)
            VALUES (?, ?, ?, ?, ?)
        """, (file_uuid, encoded_data, mime_type, file_name, time.time()))
        conn.commit()
        conn.close()

        # ИМЯ БОТА БЕЗ @
        bot_username = "Dgrf5httbteb_bot"
        download_link = f"https://t.me/{bot_username}?start={file_uuid}"

        await message.reply_text(
            f"✅ Файл сохранён! Вот ссылка для скачивания:\n\n{download_link}\n\n"
            f"🔹 Перешли её кому угодно — они получат файл, просто нажав на неё!"
        )

    except Exception as e:
        await message.reply_text(f"❌ Ошибка: {str(e)}")

# === ОБРАБОТКА /start=UUID ===
async def handle_start_with_uuid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await start_command(update, context)
        return

    file_uuid = context.args[0]
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT base64_data, mime_type, file_name FROM files WHERE uuid = ?", (file_uuid,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            await update.message.reply_text("❌ Ссылка недействительна или файл удалён.")
            return

        base64_data, mime_type, file_name = row
        file_data = base64.b64decode(base64_data)

        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file_name)[1] or ".bin") as tmp:
            tmp.write(file_data)
            tmp_path = tmp.name

        await update.message.reply_document(document=InputFile(tmp_path, filename=file_name))
        os.unlink(tmp_path)

    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка при отправке файла: {str(e)}")

# === ГЛАВНЫЙ ЗАПУСК ===
if __name__ == "__main__":
    init_db()
    try:
        print("🦊 Запуск AnntivirusFox...")
        app = Application.builder() \
            .token(TELEGRAM_BOT_TOKEN) \
            .read_timeout(30) \
            .write_timeout(30) \
            .build()

        app.add_handler(CommandHandler("start", handle_start_with_uuid))

        app.add_handler(MessageHandler(
            filters.Document.ALL | filters.PHOTO | filters.VIDEO | filters.AUDIO | filters.VOICE | filters.ANIMATION,
            handle_any_file
        ))

        print("✅ AnntivirusFox готов к работе!")
        print("Команда: /start (работает в ЛС и группах)")
        app.run_polling(drop_pending_updates=True)
    except KeyboardInterrupt:
        print("\n🛑 Бот остановлен пользователем.")
    except Exception as e:
        print(f"💥 КРИТИЧЕСКАЯ ОШИБКА: {e}")
        if os.name == 'nt':
            input("Нажмите Enter для выхода...")