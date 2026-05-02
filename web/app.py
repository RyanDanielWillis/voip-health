import os
import sys
import json
import sqlite3
from flask import Flask, request, jsonify, render_template

# Make the ``scanner`` package importable when ``web/app.py`` is run directly.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from scanner.results import flatten_audit, first_or_empty  # noqa: E402

app = Flask(__name__)
DB_NAME = os.environ.get('AVS_DB', 'audit_data.db')


def _get_conn():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = _get_conn()
    conn.execute(
        'CREATE TABLE IF NOT EXISTS audits ('
        ' id INTEGER PRIMARY KEY AUTOINCREMENT,'
        ' data TEXT'
        ')'
    )
    conn.commit()
    conn.close()


def _load_audits(limit=None):
    """Return a list of audits, each enriched with a ``fields`` dict
    derived from the raw payload via :func:`flatten_audit`."""
    conn = _get_conn()
    cur = conn.cursor()
    sql = 'SELECT id, data FROM audits ORDER BY id DESC'
    if limit:
        sql += ' LIMIT ?'
        cur.execute(sql, (limit,))
    else:
        cur.execute(sql)
    out = []
    for row_id, raw in cur.fetchall():
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            payload = {"_unparseable": raw}
        out.append({
            "id": row_id,
            "data": payload,
            "fields": first_or_empty(payload),
            "results": flatten_audit(payload),
        })
    conn.close()
    return out


@app.route("/")
def index():
    recent = _load_audits(limit=6)
    return render_template("index.html", recent_audits=recent)


@app.route('/api/upload-audit', methods=['POST'])
def upload_audit():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "No JSON provided"}), 400

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('INSERT INTO audits (data) VALUES (?)', (json.dumps(data),))
    audit_id = cur.lastrowid
    conn.commit()
    conn.close()

    structured = flatten_audit(data)
    return jsonify({
        "status": "success",
        "id": audit_id,
        "results": structured,
        "count": len(structured),
    }), 200


@app.route('/api/audits', methods=['GET'])
def list_audits():
    """JSON feed of structured audits — useful for charts / external tools."""
    rows = _load_audits()
    return jsonify({
        "count": len(rows),
        "audits": [
            {"id": r["id"], "fields": r["fields"], "results": r["results"]}
            for r in rows
        ],
    })


@app.route('/dashboard')
def dashboard():
    rows = _load_audits()
    return render_template('dashboard.html', data=rows)


init_db()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
