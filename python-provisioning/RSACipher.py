from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import rsa
import base64


class RSACipher(object):

    def __init__(self, pub_key, priv_key, encoding):
        """Initializes a RSA cipher object
        :param pub_key: Public key in PEM format
        :param priv_key: Private key in PEM format
        :param encoding: Charset encoding. Default is utf-8
        """
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.rsa_priv_key = rsa.PrivateKey.load_pkcs1(priv_key)
        self.rsa_dec = PKCS1_v1_5.new(RSA.importKey(priv_key))

        if pub_key is not None:
            self.rsa_enc = PKCS1_v1_5.new(RSA.importKey(pub_key))
        else:
            self.rsa_enc = PKCS1_v1_5.new(RSA.importKey(priv_key))

        if encoding is None:
            self.encoding = "utf-8"
        else:
            self.encoding = encoding

    def encrypt(self, message):
        """Encrypts data
        :param message: Data to be encrypted
        :return: Encrypted data
        """
        message = message.encode(self.encoding)
        message = self.rsa_enc.encrypt(message)
        return base64.b64encode(message).decode(self.encoding)

    def decrypt(self, message):
        """Decrypts data
        :param message: Data to be decrypted
        :return: Decrypted data
        """
        sentinel = ""
        message = base64.b64decode(message.encode(self.encoding))
        plain_text = self.rsa_dec.decrypt(message, sentinel).decode(self.encoding)
        return plain_text

    def sign(self, message):
        """Sign a message
        :param message: Data to be signed
        :return: Signed data
        """
        message = message.encode(self.encoding)
        message = rsa.sign(message, self.rsa_priv_key, "SHA-256")
        signed = base64.b64encode(message).decode()
        return signed
