import secrets
import randomgen as rg
import warnings

warnings.filterwarnings("ignore", "Generator", FutureWarning)


def random_bytes(n=None):
    """Return a random byte string containing *n* bytes.
       default: 16
    """
    return secrets.token_bytes(n)


def aes_random_integer(aes_seed, low, high, size=None):
    """
    Return random integers from `low` (inclusive) to `high` (exclusive)
    """
    generator = rg.Generator(rg.AESCounter(aes_seed, mode="legacy"))
    random_integer = generator.integers(low, high, size)
    return random_integer


if __name__ == '__main__':
    seed = 99  # np.random.randint(0, 10000)
    print(aes_random_integer(seed, 0, 1000))
    print(aes_random_integer(seed, 0, 1000, size=10))
