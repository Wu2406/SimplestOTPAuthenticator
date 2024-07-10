# 简单Authenticator
## main.py 本地验证器
- 使用pyopt进行TOPT算法的认证功能。
- 使用fernet（AES算法）对本地secret_key进行加密储存，保证安全。

## OTPServer.py 一个简单的服务端测试程序
- 用secret_key生成OTP验证码
- 可以随机生成新的secret_key
