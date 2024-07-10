import pyotp
import time
secret_key = input('输入secret key(不输入的话会随机生成): ')
if secret_key == '':
    secret_key = pyotp.random_base32()

print("Secret Key: " + secret_key)
totp = pyotp.TOTP(secret_key)
while True:
    print("TOTP Key: " + totp.now())
    time.sleep(5)