import random
import string
from dataclasses import dataclass


@dataclass
class PasswordConfig:
    """密码生成配置"""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False  # 排除易混淆字符 (0O, 1lI)


class PasswordGenerator:
    """密码生成器"""

    AMBIGUOUS_CHARS = "0O1lI"

    @staticmethod
    def generate(config: PasswordConfig = None) -> str:
        """根据配置生成随机密码"""
        if config is None:
            config = PasswordConfig()

        chars = ""
        required = []

        if config.use_lowercase:
            pool = string.ascii_lowercase
            if config.exclude_ambiguous:
                pool = "".join(c for c in pool if c not in PasswordGenerator.AMBIGUOUS_CHARS)
            chars += pool
            required.append(random.choice(pool))

        if config.use_uppercase:
            pool = string.ascii_uppercase
            if config.exclude_ambiguous:
                pool = "".join(c for c in pool if c not in PasswordGenerator.AMBIGUOUS_CHARS)
            chars += pool
            required.append(random.choice(pool))

        if config.use_digits:
            pool = string.digits
            if config.exclude_ambiguous:
                pool = "".join(c for c in pool if c not in PasswordGenerator.AMBIGUOUS_CHARS)
            chars += pool
            required.append(random.choice(pool))

        if config.use_symbols:
            pool = string.punctuation
            chars += pool
            required.append(random.choice(pool))

        if not chars:
            chars = string.ascii_letters + string.digits

        # 生成密码，确保包含所有必需字符类型
        remaining_length = config.length - len(required)
        password_chars = required + [random.choice(chars) for _ in range(remaining_length)]
        random.shuffle(password_chars)

        return "".join(password_chars)

    @staticmethod
    def calculate_strength(password: str) -> tuple[int, str]:
        """计算密码强度，返回 (分数, 描述)"""
        score = 0

        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        score += char_types

        if score <= 2:
            return score, "弱"
        elif score <= 4:
            return score, "中"
        elif score <= 6:
            return score, "强"
        else:
            return score, "非常强"
