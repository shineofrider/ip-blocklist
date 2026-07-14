import os
import re
import time
import poplib
import imaplib
import email
import sqlite3
import logging
import ipaddress
import threading

from datetime import datetime, timedelta
from email.header import decode_header
from flask import Flask, Response


DB_FILE = "/data/ip_blocklist.db"

app = Flask(__name__)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s"
)

IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)


def getenv_bool(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "y", "on")


def get_mail_protocol():
    return os.getenv("MAIL_PROTOCOL", "imap").strip().lower()


def get_poll_interval():
    return int(os.getenv("POLL_INTERVAL", "300"))


def get_retention_days():
    return int(os.getenv("RETENTION_DAYS", "60"))


def get_exclusion_items():
    filename = "/config/exclusions.txt"

    if not os.path.exists(filename):
        return []

    items = []

    with open(filename, "r", encoding="utf-8") as f:

        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            items.append(line)

    return items


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ips (
            ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def decode_mime_header(value):
    if not value:
        return ""

    decoded_parts = decode_header(value)
    result = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="ignore")
        else:
            result += part

    return result


def strip_html(html):
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    html = re.sub(r"(?s)<.*?>", " ", html)

    replacements = {
        "&nbsp;": " ",
        "&lt;": "<",
        "&gt;": ">",
        "&amp;": "&",
        "&quot;": '"',
        "&#39;": "'"
    }

    for old, new in replacements.items():
        html = html.replace(old, new)

    return html


def extract_text_from_email(msg):
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition.lower():
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            charset = part.get_content_charset() or "utf-8"

            try:
                decoded = payload.decode(charset, errors="ignore")
            except Exception:
                decoded = payload.decode("utf-8", errors="ignore")

            if content_type == "text/plain":
                body_parts.append(decoded)

            elif content_type == "text/html":
                body_parts.append(strip_html(decoded))

    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"

            try:
                decoded = payload.decode(charset, errors="ignore")
            except Exception:
                decoded = payload.decode("utf-8", errors="ignore")

            if msg.get_content_type() == "text/html":
                decoded = strip_html(decoded)

            body_parts.append(decoded)

    return "\n".join(body_parts)


def extract_ipv4_addresses(text):
    return sorted(set(IPV4_REGEX.findall(text)))


def build_exclusions(exclude_list):
    exclusions = []

    for item in exclude_list:
        try:
            if "/" in item:
                exclusions.append(
                    ipaddress.ip_network(item, strict=False)
                )
            else:
                exclusions.append(
                    ipaddress.ip_address(item)
                )

        except ValueError:
            logging.warning("Esclusione non valida ignorata: %s", item)

    return exclusions


def is_excluded(ip, exclusions):
    try:
        ip_obj = ipaddress.ip_address(ip)

        for exclusion in exclusions:
            if isinstance(exclusion, ipaddress.IPv4Address):
                if ip_obj == exclusion:
                    return True
            else:
                if ip_obj in exclusion:
                    return True

        return False

    except ValueError:
        return True


def filter_ips(found_ips, exclusions):
    return [
        ip
        for ip in found_ips
        if not is_excluded(ip, exclusions)
    ]


def save_ips(ips):
    if not ips:
        return 0

    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    inserted = 0

    for ip in ips:
        try:
            cur.execute("""
                INSERT INTO ips (
                    ip,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?)
            """, (ip, now, now))

            inserted += 1

        except sqlite3.IntegrityError:
            cur.execute("""
                UPDATE ips
                SET last_seen = ?
                WHERE ip = ?
            """, (now, ip))

    conn.commit()
    conn.close()

    return inserted


def cleanup_old_ips(retention_days):
    if retention_days <= 0:
        return

    limit_date = datetime.utcnow() - timedelta(days=retention_days)
    limit_text = limit_date.isoformat(timespec="seconds")

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM ips
        WHERE last_seen < ?
    """, (limit_text,))

    deleted = cur.rowcount

    conn.commit()
    conn.close()

    if deleted:
        logging.info("Eliminati %s IP più vecchi di %s giorni", deleted, retention_days)


def get_all_ips():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT ip
        FROM ips
    """)

    rows = cur.fetchall()
    conn.close()

    ips = [row[0] for row in rows]

    return sorted(
        ips,
        key=lambda value: ipaddress.ip_address(value)
    )


def process_email_message(raw_email, exclusions):
    msg = email.message_from_bytes(raw_email)

    subject = decode_mime_header(msg.get("Subject", ""))
    sender = decode_mime_header(msg.get("From", ""))

    body = extract_text_from_email(msg)

    found_ips = extract_ipv4_addresses(body)
    filtered_ips = filter_ips(found_ips, exclusions)

    inserted = save_ips(filtered_ips)

    logging.info(
        "Email processata. Mittente=%s, Oggetto=%s, IP trovati=%s, IP validi=%s, IP nuovi=%s",
        sender,
        subject,
        len(found_ips),
        len(filtered_ips),
        inserted
    )


def process_imap_mailbox(exclusions):
    host = os.getenv("MAIL_HOST")
    port = int(os.getenv("MAIL_PORT", "993"))
    username = os.getenv("MAIL_USER")
    password = os.getenv("MAIL_PASSWORD")
    mailbox = os.getenv("IMAP_MAILBOX", "INBOX")
    use_ssl = getenv_bool("MAIL_SSL", "true")

    if not host or not username or not password:
        logging.error("Configurazione IMAP incompleta")
        return

    logging.info("Connessione IMAP a %s:%s", host, port)

    if use_ssl:
        mail = imaplib.IMAP4_SSL(host, port)
    else:
        mail = imaplib.IMAP4(host, port)

    try:
        mail.login(username, password)
        mail.select(mailbox)

        status, data = mail.search(None, "ALL")

        if status != "OK":
            logging.warning("Impossibile cercare messaggi nella mailbox IMAP")
            return

        message_ids = data[0].split()

        if not message_ids:
            logging.info("Nessuna email IMAP da processare")
            return

        logging.info("Email IMAP trovate: %s", len(message_ids))

        for msg_id in message_ids:
            try:
                status, msg_data = mail.fetch(msg_id, "(RFC822)")

                if status != "OK":
                    logging.warning("Impossibile leggere email IMAP ID %s", msg_id)
                    continue

                raw_email = msg_data[0][1]

                process_email_message(raw_email, exclusions)

                mail.store(msg_id, "+FLAGS", "\\Deleted")

            except Exception as e:
                logging.exception("Errore processamento email IMAP ID %s: %s", msg_id, e)

        mail.expunge()

    finally:
        try:
            mail.logout()
        except Exception:
            pass


def process_pop3_mailbox(exclusions):
    host = os.getenv("MAIL_HOST")
    port = int(os.getenv("MAIL_PORT", "995"))
    username = os.getenv("MAIL_USER")
    password = os.getenv("MAIL_PASSWORD")
    use_ssl = getenv_bool("MAIL_SSL", "true")

    if not host or not username or not password:
        logging.error("Configurazione POP3 incompleta")
        return

    logging.info("Connessione POP3 a %s:%s", host, port)

    if use_ssl:
        mail = poplib.POP3_SSL(host, port)
    else:
        mail = poplib.POP3(host, port)

    try:
        mail.user(username)
        mail.pass_(password)

        message_count, mailbox_size = mail.stat()

        if message_count == 0:
            logging.info("Nessuna email POP3 da processare")
            return

        logging.info("Email POP3 trovate: %s", message_count)

        for index in range(1, message_count + 1):
            try:
                response, lines, octets = mail.retr(index)
                raw_email = b"\n".join(lines)

                process_email_message(raw_email, exclusions)

                mail.dele(index)

            except Exception as e:
                logging.exception("Errore processamento email POP3 numero %s: %s", index, e)

    finally:
        try:
            mail.quit()
        except Exception:
            pass


def process_mailbox():
    retention_days = get_retention_days()
    exclusion_items = get_exclusion_items()
    exclusions = build_exclusions(exclusion_items)
    protocol = get_mail_protocol()

    cleanup_old_ips(retention_days)

    if protocol == "imap":
        process_imap_mailbox(exclusions)

    elif protocol in ("pop", "pop3"):
        process_pop3_mailbox(exclusions)

    else:
        logging.error("Protocollo non valido: %s. Usa MAIL_PROTOCOL=imap oppure MAIL_PROTOCOL=pop3", protocol)


def mail_worker():
    interval_seconds = get_poll_interval()

    logging.info("Worker avviato. Intervallo controllo: %s secondi", interval_seconds)

    while True:
        try:
            process_mailbox()
        except Exception as e:
            logging.exception("Errore generale nel worker: %s", e)

        time.sleep(interval_seconds)


@app.route("/")
def index():
    ips = get_all_ips()
    output = "\n".join(ips)

    if output:
        output += "\n"

    return Response(
        output,
        mimetype="text/plain; charset=utf-8"
    )


@app.route("/health")
def health():
    return Response(
        "OK\n",
        mimetype="text/plain; charset=utf-8"
    )


if __name__ == "__main__":
    init_db()

    worker = threading.Thread(target=mail_worker, daemon=True)
    worker.start()

    web_host = os.getenv("WEB_HOST", "0.0.0.0")
    web_port = int(os.getenv("WEB_PORT", "80"))

    app.run(
        host=web_host,
        port=web_port
    )