import os
import qrcode

# Sample URLs: 2 safe, 3 that mimic common phishing tricks
SAMPLES = {
    "safe_google.png": "https://www.google.com",
    "safe_karunya.png": "https://www.karunya.edu",
    "phish_paypal_lookalike.png": "http://paypa1-secure-login.com/verify/account",
    "phish_ip_address.png": "http://192.168.10.5/bank/login.php",
    "phish_shortener.png": "http://bit.ly/3xYzAbC",
}

# Create a folder called test_qrs (skip if it already exists)
os.makedirs("test_qrs", exist_ok=True)

# Turn each URL into a QR code image and save it
for filename, url in SAMPLES.items():
    qrcode.make(url).save(os.path.join("test_qrs", filename))
    print(f"Created {filename} -> {url}")