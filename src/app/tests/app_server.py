from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/notification', methods=['POST'])
def notification():
    data = request.get_json()
    # Process the data as needed
    return jsonify({"status": "received", "data": data}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

#NOTE This is a simple Flask server to receive notifications for testing purposes.