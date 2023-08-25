import random
import string


def generate(length=32):
    """Generate a random token for use in account tokens.

    param: length - the length of the token to generate
    """
    alpha = string.ascii_letters + string.digits
    token = "".join(random.SystemRandom().choice(alpha) for _ in range(length))
    return token
