from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import base64

class PrpCrypt(object):
    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, self.mode, b'0123456789ABCDEF')
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            # \0 backspace
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        self.ciphertext = cryptor.encrypt(text)
        return base64.b64encode(self.ciphertext).decode()

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0123456789ABCDEF')
        decryptByts = base64.b64decode(text)
        plain_text = cryptor.decrypt(decryptByts)
        return bytes.decode(plain_text).rstrip('\0')


if __name__ == '__main__':
    pc = PrpCrypt('jo8j9wGw%6HbxfFn')  # 初始化密钥 key
    e = pc.encrypt('{"code":200,"data":{"apts":[]},"message":"","success":true}')  # 加密
    d = pc.decrypt("lXgLoJQ3MAUdzLX+ORj5/pJlkRAU423JfyUKVd5IwfCSxw6d1mHwBdHV9p3kmKCYwNRmAIEWeb/9ypLCqTZ1FA==")  # 解密
    print("加密:", e)
    print("解密:", d)