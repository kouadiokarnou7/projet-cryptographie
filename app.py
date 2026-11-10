import sqlite3
import json
from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_engine import P, G

app = Flask(__name__)
DB_NAME = "messenger_db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pseudo TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS room_members (
                room_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY(room_id, user_id),
                FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                c1 TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS message_envelopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                c2_blocks TEXT NOT NULL,
                FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
                FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/app")
def messenger_app():
    return render_template("app.html")

@app.route("/api/crypto/params", methods=["GET"])
def get_crypto_params():
    return jsonify({
        "p": str(P),
        "g": str(G)
    })

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    pseudo = data.get("pseudo", "").strip()
    password = data.get("password", "").strip()
    public_key = data.get("public_key", "").strip()

    if not pseudo or not password or not public_key:
        return jsonify({"error": "Pseudo, mot de passe et clé publique requis."}), 400

    hashed_pw = generate_password_hash(password)
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (pseudo, password_hash, public_key) VALUES (?, ?, ?)",
                (pseudo, hashed_pw, public_key)
            )
            user_id = cursor.lastrowid
            conn.commit()
            return jsonify({
                "id": user_id,
                "pseudo": pseudo,
                "public_key": public_key
            }), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ce pseudo est déjà utilisé."}), 409

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    pseudo = data.get("pseudo", "").strip()

    if not pseudo:
        return jsonify({"error": "Pseudo requis."}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, pseudo, public_key FROM users WHERE pseudo = ?", (pseudo,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Utilisateur introuvable."}), 404

        return jsonify({
            "id": user["id"],
            "pseudo": user["pseudo"],
            "public_key": user["public_key"]
        }), 200

@app.route("/api/users", methods=["GET"])
def list_users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, pseudo, public_key FROM users ORDER BY pseudo ASC")
        users = [dict(row) for row in cursor.fetchall()]
        return jsonify(users), 200

@app.route("/api/rooms", methods=["GET"])
def get_user_rooms():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"error": "user_id requis."}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.id, r.name, r.created_by, r.created_at
            FROM rooms r
            JOIN room_members rm ON r.id = rm.room_id
            WHERE rm.user_id = ?
            ORDER BY r.created_at DESC
        """, (user_id,))
        rooms = [dict(row) for row in cursor.fetchall()]

        for room in rooms:
            cursor.execute("""
                SELECT u.id, u.pseudo, u.public_key
                FROM users u
                JOIN room_members rm ON u.id = rm.user_id
                WHERE rm.room_id = ?
            """, (room["id"],))
            room["members"] = [dict(m) for m in cursor.fetchall()]

        return jsonify(rooms), 200

@app.route("/api/rooms", methods=["POST"])
def create_room():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    created_by = data.get("created_by")
    member_ids = data.get("member_ids", [])

    if not name or not created_by or not member_ids:
        return jsonify({"error": "Nom du salon, créateur et participants requis."}), 400

    if created_by not in member_ids:
        member_ids.append(created_by)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO rooms (name, created_by) VALUES (?, ?)", (name, created_by))
        room_id = cursor.lastrowid

        for mid in set(member_ids):
            cursor.execute("INSERT INTO room_members (room_id, user_id) VALUES (?, ?)", (room_id, mid))

        conn.commit()

        cursor.execute("""
            SELECT u.id, u.pseudo, u.public_key
            FROM users u
            JOIN room_members rm ON u.id = rm.user_id
            WHERE rm.room_id = ?
        """, (room_id,))
        members = [dict(m) for m in cursor.fetchall()]

        return jsonify({
            "id": room_id,
            "name": name,
            "created_by": created_by,
            "members": members
        }), 201

@app.route("/api/rooms/<int:room_id>/messages", methods=["GET"])
def get_room_messages(room_id):
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"error": "user_id requis."}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.id, m.room_id, m.sender_id, u.pseudo as sender_pseudo, m.c1, m.created_at,
                   me.c2_blocks
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            LEFT JOIN message_envelopes me ON m.id = me.message_id AND me.recipient_id = ?
            WHERE m.room_id = ?
            ORDER BY m.created_at ASC
        """, (user_id, room_id))

        messages = []
        for row in cursor.fetchall():
            item = dict(row)
            if item["c2_blocks"]:
                try:
                    item["c2_blocks"] = json.loads(item["c2_blocks"])
                except Exception:
                    item["c2_blocks"] = []
            else:
                item["c2_blocks"] = None
            messages.append(item)

        return jsonify(messages), 200

@app.route("/api/rooms/<int:room_id>/messages", methods=["POST"])
def send_message(room_id):
    data = request.get_json() or {}
    sender_id = data.get("sender_id")
    c1 = data.get("c1")
    envelopes = data.get("envelopes", [])

    if not sender_id or not c1 or not envelopes:
        return jsonify({"error": "sender_id, c1 et enveloppes chiffrées requis."}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO messages (room_id, sender_id, c1) VALUES (?, ?, ?)",
            (room_id, sender_id, str(c1))
        )
        message_id = cursor.lastrowid

        for env in envelopes:
            recipient_id = env.get("recipient_id")
            c2_blocks = env.get("c2_blocks", [])
            c2_json = json.dumps([str(b) for b in c2_blocks])
            cursor.execute(
                "INSERT INTO message_envelopes (message_id, recipient_id, c2_blocks) VALUES (?, ?, ?)",
                (message_id, recipient_id, c2_json)
            )

        conn.commit()
        return jsonify({"status": "success", "message_id": message_id}), 201

@app.route("/api/sniffer", methods=["GET"])
def sniffer_view():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                m.id AS message_id,
                r.name AS room_name,
                sender.pseudo AS sender_pseudo,
                m.c1,
                recipient.pseudo AS recipient_pseudo,
                me.c2_blocks,
                m.created_at
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN users sender ON m.sender_id = sender.id
            JOIN message_envelopes me ON m.id = me.message_id
            JOIN users recipient ON me.recipient_id = recipient.id
            ORDER BY m.id DESC, recipient.id ASC
            LIMIT 50
        """)
        rows = [dict(r) for r in cursor.fetchall()]
        return jsonify(rows), 200

if __name__ == "__main__":
    init_db()
    # host="0.0.0.0" permet aux autres appareils du meme reseau Wi-Fi d'acceder au serveur
    app.run(debug=True, host="0.0.0.0", port=5000)

