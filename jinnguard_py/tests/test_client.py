import os
import struct
import unittest
from unittest.mock import patch

from jinnguard.client import JinnGuardClient


class FakeSocket:
    def __init__(self, response_chunks):
        self.response_chunks = list(response_chunks)
        self.timeout = None
        self.closed = False
        self.sent = b""

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, socket_path):
        self.socket_path = socket_path

    def sendall(self, data):
        self.sent += data

    def recv(self, _size):
        if not self.response_chunks:
            return b""
        return self.response_chunks.pop(0)

    def close(self):
        self.closed = True


class JinnGuardClientTests(unittest.TestCase):
    def setUp(self):
        os.environ["JINN_GUARD_SECRET"] = "test-secret"

    def tearDown(self):
        os.environ.pop("JINN_GUARD_SECRET", None)

    def test_auto_sequence_counter_is_monotonic(self):
        client = JinnGuardClient(socket_path="/tmp/jinnguard-test.sock")

        first = client._build_payload(
            "read_file",
            risk_score=1.0,
            sequence_counter=None,
            privilege=0.0,
            prompt=None,
            plan=None,
            source_code=None,
            requested_capabilities=None,
            execute=False,
        )
        second = client._build_payload(
            "write_file",
            risk_score=1.0,
            sequence_counter=None,
            privilege=0.0,
            prompt=None,
            plan=None,
            source_code=None,
            requested_capabilities=None,
            execute=False,
        )

        self.assertGreater(second["sequence_counter"], first["sequence_counter"])

    def test_oversized_response_frame_is_rejected_before_body_read(self):
        fake_socket = FakeSocket([struct.pack(">IB", 1024, 1)])

        with patch("jinnguard.client.socket.socket", return_value=fake_socket):
            client = JinnGuardClient(
                socket_path="/tmp/jinnguard-test.sock",
                timeout=0.1,
                max_response_bytes=8,
            )
            response = client.send_proposal("read_file")

        self.assertEqual(
            response,
            "TRANSPORT_ERROR: Response frame too large (1024 > 8)",
        )
        self.assertTrue(fake_socket.closed)


if __name__ == "__main__":
    unittest.main()
