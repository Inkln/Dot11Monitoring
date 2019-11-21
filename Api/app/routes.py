from ..app import app
from flask import request, jsonify

@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

@app.route('/add_result', methods=['POST'])
def receive_scanner_result():
    result = request.get_json()
    print(result)
    return 'OK'

@app.route('/hi')
def hi():
    return 'Hehe'