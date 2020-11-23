import secrets


def random_bytes(n=None):
    """Return a random byte string containing *n* bytes.
       default: 16
    """
    return secrets.token_bytes(n)


if __name__ == '__main__':
    print(random_bytes(16))
