# backend.py
from flask import Flask, request, jsonify, render_template
app = Flask(__name__)

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    if data.get("username") == "sydeco" and data.get("password") == "123":
        return jsonify({"status": "ok", "token": "jwt123", "from" : "backend 2"})
    return jsonify({"status": "fail"}), 401

@app.route("/api/data", methods=["POST"])
def data():
    return jsonify({"status": "ok", "data": request.json , "from" : "backend 2"})

@app.route('/view', methods=["GET"])
def view_page():
    # return jsonify({"status": "ok", "page": "This is a view page from backend 2", "from" : "backend 2"})
    return render_template('tes.html')
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7003)

