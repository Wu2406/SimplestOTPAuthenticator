import sys

import qrcode
import pyotp
import base64
import hashlib
import csv
import getpass

from cryptography.fernet import Fernet

encrypted_key_file_path = 'encrypted_key.csv'


def csv_to_dict():
    with open(encrypted_key_file_path, 'r') as file:
        reader = csv.DictReader(file)
        data = [row for row in reader]
        #print(data)
    return data


def write_csv(key_name, encrypted_key, prompt):
    csv_data = csv_to_dict()
    with open(encrypted_key_file_path, 'w', newline='') as file:
        header = ['name', 'encrypted_key', 'prompt']
        writer = csv.DictWriter(file, header)
        new_dict = {'name': key_name, 'encrypted_key': encrypted_key, 'prompt': prompt}
        csv_data.append(new_dict)
        writer.writeheader()
        writer.writerows(csv_data)


def generate_key(password: str) -> bytes:
    # 使用SHA-256哈希函数生成32字节的密钥
    password_bytes = password.encode('utf-8')
    return base64.urlsafe_b64encode(hashlib.sha256(password_bytes).digest())


def encrypt_message(password: str, message: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode('utf-8'))
    return encrypted_message.decode('utf-8')


def decrypt_message(password: str, encrypted_message: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message.encode('utf-8'))
    return decrypted_message.decode('utf-8')


def enc_key(password, message):
    # 加密消息
    encrypted_message = encrypt_message(password, message)
    return f"{encrypted_message}"


def dec_key(encrypted_message, password):
    # 解密消息
    decrypted_message = decrypt_message(password, encrypted_message)
    return f"{decrypted_message}"


def create_key():
    print("----------创建新的key----------")
    new_key = input("请输入网站提供的secret_key: \n    ")
    totp = pyotp.TOTP(new_key)
    now_otp = totp.now()
    print("当前的验证码为",now_otp)

    key_name = input("请给这个secret_key起名，便于区分多个key: \n    ")
    password = getpass.getpass("请输入本地加密密码,后续验证时会需要(默认不显示出来): \n    ")
    password_again = getpass.getpass("请再次输入本地加密密码(默认不显示出来): \n    ")
    while password_again != password:
        print("---密码不一致，请重新输入!---")
        password = getpass.getpass("请输入本地加密密码,后续验证时会需要(默认不显示出来): \n    ")
        password_again = getpass.getpass("请再次输入本地加密密码(默认不显示出来): \n    ")
    print("----------密码一致----------")
    prompt = input("(选填)密码提示，帮助后续回忆密码，防止密码丢失: \n    ")
    encrypted_key = enc_key(password, new_key)
    print(encrypted_key)
    write_csv(key_name, encrypted_key, prompt)


def authenticate():
    print("----------使用原有key验证----------")
    encrypted_key_data = csv_to_dict()
    print('已经保存的key:')
    print('    id  name')
    for i in range(len(encrypted_key_data)):
        print('   ',str(i).ljust(3),encrypted_key_data[i]['name'])
    id = int(input('请输入想要使用的id:'))
    if 0 <= id < len(encrypted_key_data):
        print('----------使用id',id,'进行验证----------')
        print("密码提示词:\n   ",encrypted_key_data[id]['prompt'])
        password = getpass.getpass("请输入本地加密密码(默认不显示出来): \n    ", stream=sys.stdout)
        decrypt_key = dec_key(encrypted_key_data[id]['encrypted_key'], password)
        #print(decrypt_key)
        totp = pyotp.TOTP(decrypt_key)
        now_otp = totp.now()
        print("当前的验证码为",now_otp)
        pause = input("按回车退出")
    else:
        print('id不存在')
        return


if __name__ == '__main__':
    op=input("    1:创建新的key\n    2:使用原有key验证\n请输入想要进行的操作:")
    if op=='1':
        create_key()
    elif op=='2':
        authenticate()

