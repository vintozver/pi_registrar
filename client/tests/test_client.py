import unittest
from unittest.mock import MagicMock, Mock, call, patch

from pi_registrar.client import run


class RunTests(unittest.TestCase):
    @patch("pi_registrar.client.urllib.request.build_opener")
    @patch("pi_registrar.client._make_token", return_value="token")
    @patch(
        "pi_registrar.client._resolve",
        side_effect=[("https://server", "192.0.2.1"), ("https://server", "2001:db8::1")],
    )
    def test_registers_each_selected_protocol(self, resolve, make_token, build_opener):
        first_response = Mock()
        first_response.read.return_value = b"ipv4"
        second_response = Mock()
        second_response.read.return_value = b"ipv6"
        first_opener = MagicMock()
        first_opener.open.return_value.__enter__.return_value = first_response
        second_opener = MagicMock()
        second_opener.open.return_value.__enter__.return_value = second_response
        build_opener.side_effect = [first_opener, second_opener]

        result = run(
            [
                "--endpoint",
                "https://server",
                "--certificate",
                "certificate.pem",
                "--ipv4",
                "--ipv6",
            ]
        )

        self.assertEqual(result, "ipv4\nipv6")
        self.assertEqual(resolve.call_args_list, [call("https://server", True), call("https://server", False)])
        self.assertEqual(make_token.call_args_list, [call("certificate.pem"), call("certificate.pem")])
        self.assertEqual(first_opener.open.call_count, 1)
        self.assertEqual(second_opener.open.call_count, 1)

    @patch("pi_registrar.client._register", return_value="registered")
    def test_selects_requested_protocols(self, register):
        cases = [
            ([], [False]),
            (["--ipv4"], [True]),
            (["--ipv6"], [False]),
        ]

        for flags, protocols in cases:
            with self.subTest(flags=flags):
                run(["--endpoint", "https://server", "--certificate", "certificate.pem", *flags])
                self.assertEqual(
                    register.call_args_list,
                    [call("https://server", "certificate.pem", ipv4) for ipv4 in protocols],
                )
                register.reset_mock()
