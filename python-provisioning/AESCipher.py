from Crypto.Cipher import AES
import base64


class AESCipher(object):
    PADDING = 16

    def __init__(self, key, iv, encoding):
        """Initializes a AES cipher object
        :param key:  The secret key to use in the symmetric cipher.
        It must be 16 (AES-12), 24 (AES-192), or 32 (AES-256) bytes long
        :param iv: The initialization vector to use for encryption or decryption
        :param encoding: Charset encoding. Default is utf-8
        """
        self.key = key
        self.iv = iv
        self.encoding = encoding

        if self.encoding is None:
            self.encoding = "utf-8"
        else:
            self.encoding = encoding

    def encrypt(self, plain):
        """Encrypts data
        :param plain: Data to encrypt
        :return: Encrypted data
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        length = self.PADDING - (len(plain) % self.PADDING)
        plain += chr(length) * length
        return base64.b64encode(cipher.encrypt(plain))

    def decrypt(self, encrypted):
        """Decrypts data
        :param encrypted: Data to decrypt
        :return: Decrypted data
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plain = cipher.decrypt(base64.b64decode(encrypted))
        plain = plain[:-plain[-1]]
        return str(plain, self.encoding)
