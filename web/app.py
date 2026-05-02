import sqlite3
import json
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
DB_NAME = 'audit_data.db'

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute('CREATE TABLE IF NOT EXISTS audits (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT)')
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/api/upload-audit', methods=['POST'])
def upload_audit():
    data = request.get_json()
    if data is None:
        return jsonify({"status": "error", "message": "No JSON provided"}), 400
    
    # Connect and save
    conn = sqlite3.connect(DB_NAME)
    # Convert dict to JSON string before saving
    conn.execute('INSERT INTO audits (data) VALUES (?)', (json.dumps(data),))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success"}), 200

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, data FROM audits ORDER BY id DESC')
    # Fetch rows as dicts for easy access in Jinja
    rows = [{"id": r[0], "data": json.loads(r[1])} for r in cursor.fetchall()]
    conn.close()
    return render_template('dashboard.html', data=rows)

init_db()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
