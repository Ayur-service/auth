import uuid
import random


def generate_ayur_id(x: int = 12) -> str:
    return random.randint(10 ** (x - 1), 10 ** x - 1)


if __name__ == "__main__":
    a = set()
    for i in range(10000000):
        a.add(generate_ayur_id())

    print(len(a) == 10000000)
    print(len(a))
