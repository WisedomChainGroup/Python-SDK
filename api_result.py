#!/usr/bin/python3

import json


class APIResult:
    def __init__(self, data, message):
        self.data = data
        self.message = message


if __name__ == '__main__':
    a = APIResult('123', 24)
    print(json.dumps(a.__dict__))
