from __future__ import annotations

import unittest

from scripts.render_nginx_upstream import render


class NginxUpstreamRenderTest(unittest.TestCase):
    def test_renders_loopback_address_and_port(self) -> None:
        self.assertEqual(
            render("127.0.0.2", 18100),
            "upstream mycomesh_gateway {\n"
            "    server 127.0.0.2:18100 max_fails=2 fail_timeout=5s;\n"
            "    keepalive 16;\n"
            "}\n",
        )

    def test_rejects_non_loopback_and_invalid_ports(self) -> None:
        for address in ("0.0.0.0", "10.0.0.1", "::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                render(address, 8100)
        for port in (0, 65536):
            with self.subTest(port=port), self.assertRaises(ValueError):
                render("127.0.0.1", port)


if __name__ == "__main__":
    unittest.main()
