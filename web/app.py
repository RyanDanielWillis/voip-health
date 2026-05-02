import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('audit_data.db')
    conn.execute('CREATE TABLE IF NOT EXISTS audits (id INTEGER PRIMARY KEY, data TEXT)')
    conn.commit()
    conn.close()

@app.route('/api/upload-audit', methods=['POST'])
def upload_audit():
    data = request.get_json()
    conn = sqlite3.connect('audit_data.db')
    conn.execute('INSERT INTO audits (data) VALUES (?)', (str(data),))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"}), 200

init_db()
if __name__ == '__main__':
    app.run(port=5000)
