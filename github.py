from flask import Flask, request, jsonify
import requests
import hashlib
import hmac
import os

app = Flask(__name__)

# 你的GitHub webhook秘钥
GITHUB_SECRET = os.getenv('GITHUB_SECRET')
# 你的飞书机器人webhook URL
FEISHU_WEBHOOK_URL = os.getenv('FEISHU_WEBHOOK_URL')

def verify_signature(data, signature):
    """验证GitHub的签名"""
    github_secret = bytes(GITHUB_SECRET, 'utf-8')
    expected_signature = hmac.new(github_secret, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def send_to_feishu(message):
    """发送消息到飞书机器人"""
    headers = {'Content-Type': 'application/json'}
    payload = {
        "msg_type": "text",
        "content": {
            "text": message
        }
    }
    response = requests.post(FEISHU_WEBHOOK_URL, json=payload, headers=headers)
    return response.json()

@app.route('/webhook', methods=['POST'])
def webhook():
    # 验证签名
    signature = request.headers.get('X-Hub-Signature-256').split('=')[1] if request.headers.get('X-Hub-Signature-256') else None
    if not verify_signature(request.data, signature):
        return jsonify({'message': 'Invalid signature'}), 403

    # 解析GitHub事件
    event = request.json
    event_type = request.headers.get('X-GitHub-Event', 'ping')

    # 根据事件类型处理
    if event_type == 'ping':
        return jsonify({'message': 'Ping event received'}), 200
    else:
        # 构建消息并发送到飞书
        message = f"GitHub Event: {event_type}\nRepository: {event['repository']['full_name']}"
        send_to_feishu(message)
        return jsonify({'message': 'Event received and processed'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
