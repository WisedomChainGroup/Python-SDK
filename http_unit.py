#!/usr/bin/python3

import http.client
import urllib.parse


class HttpUnit:
    @staticmethod
    def send_post(url: str, port: int, route: str, param: str):
        conn = http.client.HTTPConnection(url, port)
        all_route = route + "?" + param
        # params = urllib.parse.urlencode(param)
        headers = {"accept": "*/*", "connection": "Keep-Alive", "user-agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)"}
        conn.request("POST", all_route, None, headers)
        response = conn.getresponse()
        print(response.status, response.reason)
        data = response.read()
        conn.close()
        print(data)
        return data


if __name__ == '__main__':
    param = "traninfo=017e5adf6fd579219a15bbedf683e1dc81cc3d7ffcac163a017ea7502e011a915f010000000000000001fce8ec82c17bbd763e2edfbbd9ae9cb24bfa2181e166c4c8590435c6383a44650000000000000004000000003b9aca002a859715c005ec0b4f6f571c8c27394296ff322d07c773c1de7713d8261ff868c0df7bc46e4c6ef8756efbe86770bd86d22611181a4e248c6a1c7f8c1073cc04a8dab9a3828d750174c25f09ab619f55d753334600000000"
    url = "192.168.1.12"
    port = 19586
    route = "/sendTransaction"
    a = HttpUnit().send_post(url, port, route, param)
