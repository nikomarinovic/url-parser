class URLStatistics:
    def __init__(self, parser):
        self.parser = parser

    @property
    def url_length(self):
        return len(self.parser.full_url)

    @property
    def host_length(self):
        return len(self.parser.hostname)

    @property
    def path_length(self):
        return len(self.parser.path)

    @property
    def query_length(self):
        return len(self.parser.query)

    @property
    def fragment_length(self):
        return len(self.parser.fragment)

    @property
    def parameter_count(self):
        return len(self.parser.query_params)

    def get(self):
        return {
            "URL Length": self.url_length,
            "Host Length": self.host_length,
            "Path Length": self.path_length,
            "Query Length": self.query_length,
            "Fragment Length": self.fragment_length,
            "Parameters": self.parameter_count,
        }