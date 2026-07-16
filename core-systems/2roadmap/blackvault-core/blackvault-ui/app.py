"""
Blackvault UI - Flask приложение
"""
from flask import Flask, render_template, jsonify
import os

app = Flask(__name__, template_folder='dashboard', static_folder='static')


@app.route('/')
def index():
    """Главная страница"""
    try:
        return render_template('index.html')
    except Exception:
        return jsonify({"status": "Blackvault UI Running", "message": "UI service is active"}), 200


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "blackvault-ui",
        "version": "1.0.0"
    }), 200


@app.route('/api/status')
def api_status():
    """API status endpoint"""
    return jsonify({
        "service": "blackvault-ui",
        "status": "running",
        "environment": os.getenv('FLASK_ENV', 'production')
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
