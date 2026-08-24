from urllib.parse import quote, unquote


def encode(value: str):
    return quote(value, safe="")


def decode(value: str):
    return unquote(value)