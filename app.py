from flask import Flask, request, jsonify
import hashlib
import hmac
import requests
from config import APP_SECRET
from config import VERIFY_TOKEN

app = Flask(__name__)

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        # Подтверждение webhook при подключении
        if request.args.get('hub.mode') == 'subscribe' and request.args.get('hub.challenge'):
            if request.args.get('hub.verify_token') == VERIFY_TOKEN:
                return request.args['hub.challenge'], 200
            else:
                return "Verification token mismatch", 403
        else:
            return "Invalid request", 400
    elif request.method == 'POST':
        # Обработка входящих сообщений от Facebook Messenger API
        payload = request.get_data()
        if verify_signature(payload):
            data = request.json
            handle_message(data)
            return jsonify({'status': 'ok'})
        else:
            return jsonify({'status': 'error', 'message': 'Signature verification failed'}), 403

def verify_signature(payload):
    signature = request.headers.get('X-Hub-Signature')
    if signature is None:
        return False

    hash_method, hash_value = signature.split('=')
    if hash_method != 'sha1':
        return False

    hmac_obj = hmac.new(bytes(APP_SECRET, 'latin-1'), payload, hashlib.sha1)
    hash_computed = hmac_obj.hexdigest()

    return hmac.compare_digest(hash_value, hash_computed)

def handle_message(data):
    # Обработка входящего сообщения от Facebook Messenger API
    # Здесь вы можете добавить логику для обработки сообщений и отправки ответов пользователю
    pass

if __name__ == '__main__':
    app.run(debug=True)
