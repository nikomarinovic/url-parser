from collections import Counter
from urllib.parse import parse_qsl, unquote


class QueryAnalyzer:
    def __init__(self, parser):
        self.parser = parser

    @property
    def parameters(self):
        return parse_qsl(
            self.parser.query,
            keep_blank_values=True
        )

    @property
    def count(self):
        return len(self.parameters)

    @property
    def unique_count(self):
        return len(set(
            key for key, _ in self.parameters
        ))

    @property
    def duplicate_parameters(self):
        keys = [
            key
            for key, _ in self.parameters
        ]

        return [
            key
            for key, count in Counter(keys).items()
            if count > 1
        ]

    @property
    def empty_parameters(self):
        return [
            key
            for key, value in self.parameters
            if value == ""
        ]

    @property
    def decoded_parameters(self):
        return [
            (
                unquote(key),
                unquote(value)
            )
            for key, value in self.parameters
        ]

    def get(self):
        return {
            "count": self.count,
            "unique": self.unique_count,
            "duplicates": self.duplicate_parameters,
            "empty": self.empty_parameters,
            "parameters": self.decoded_parameters,
        }