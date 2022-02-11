from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest import TestCase
import threading
import json

from api.uleska_api import UleskaApi

last_auth_header = None
last_body = None


class UleskaApiTest(TestCase):

    def test_get_works_with_correct_header(self):
        # given
        with HTTPServer(('localhost', 9000), TestWebServer) as web_server:
            threading.Thread(target=web_server.serve_forever, daemon=True).start()

            token = 'abc123'
            expected_token = 'Bearer abc123'

            # when
            api = UleskaApi('http://localhost:9000', token)

            api.get('/')

            # then
            self.assertEqual(expected_token, last_auth_header)
            web_server.shutdown()

    def test_post_works_with_correct_header(self):
        # given
        with HTTPServer(('localhost', 9000), TestWebServer) as web_server:
            threading.Thread(target=web_server.serve_forever, daemon=True).start()
            token = 'xyz098'
            expected_token = 'Bearer xyz098'

            # when
            api = UleskaApi('http://localhost:9000', token)

            api.post('/', {'hi': 'world'})

            # then
            self.assertEqual(expected_token, last_auth_header)
            web_server.shutdown()

    def test_post_sends_correct_json(self):
        with HTTPServer(('localhost', 9000), TestWebServer) as web_server:
            threading.Thread(target=web_server.serve_forever, daemon=True).start()
            json_data = {'some': 'thing'}

            # when
            api = UleskaApi('http://localhost:9000', 'fds')

            api.post('/', json_data)

            # then
            self.assertEqual(json_data, last_body)
            web_server.shutdown()

    def test_is_singleton(self):
        api1 = UleskaApi('some address', 'some token')
        api2 = UleskaApi()
        self.assertEqual(api1, api2)


class TestWebServer(BaseHTTPRequestHandler):

    def save_auth_header(self):
        auth_header = self.headers.get('authorization')
        if auth_header is not None:
            global last_auth_header
            last_auth_header = auth_header

    def save_body(self):
        data_size = int(self.headers.get('Content-Length'))
        global last_body
        last_body = json.loads(self.rfile.read(data_size))

    def respond_with_ok(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes('ok', 'utf-8'))

    def do_GET(self):
        self.save_auth_header()
        self.respond_with_ok()

    def do_POST(self):
        self.save_auth_header()
        self.save_body()
        self.respond_with_ok()
