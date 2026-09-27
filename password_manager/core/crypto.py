import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """加密解密管理器"""

    ITERATIONS = 480000

    def __init__(self, master_password: str, salt: bytes = None):
        self.salt = salt if salt else os.urandom(16)
        self._key = self._derive_key(master_password)
        self._cipher = Fernet(self._key)

    def _derive_key(self, password: str) -> bytes:
        """从主密码派生加密密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, data: str) -> str:
        """加密字符串，返回base64编码的密文"""
        encrypted = self._cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """解密base64编码的密文"""
        encrypted = base64.b64decode(encrypted_data.encode())
        return self._cipher.decrypt(encrypted).decode()

    def get_salt_base64(self) -> str:
        """获取base64编码的salt"""
        return base64.b64encode(self.salt).decode()

    @classmethod
    def from_salt_base64(cls, master_password: str, salt_b64: str) -> "CryptoManager":
        """从base64编码的salt创建实例"""
        salt = base64.b64decode(salt_b64.encode())
        return cls(master_password, salt)

    @staticmethod
    def verify_password(master_password: str, salt_b64: str, encrypted_test: str) -> bool:
        """验证主密码是否正确"""
        try:
            crypto = CryptoManager.from_salt_base64(master_password, salt_b64)
            crypto.decrypt(encrypted_test)
            return True
        except Exception:
            return False
