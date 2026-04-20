import re
import unittest

import waf_app


class WafAppTests(unittest.TestCase):
    def setUp(self):
        self.client = waf_app.app.test_client()
        waf_app.blocked_log.clear()
        waf_app.allowed_log.clear()
        waf_app.login_attempts.clear()
        waf_app.fragment_streams.clear()
        waf_app.traffic_profiles.clear()
        for rule_name in waf_app.RULE_STATES:
            waf_app.RULE_STATES[rule_name] = True

    def _get_login_token(self):
        response = self.client.get("/login")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def test_allowed_search_escapes_markup(self):
        response = self.client.get("/search?q=%3Cb%3Ehello%3C/b%3E")
        page = response.data.decode("utf-8", errors="replace")

        self.assertEqual(response.status_code, 200)
        self.assertIn("&lt;b&gt;hello&lt;/b&gt;", page)
        self.assertNotIn("<code><b>hello</b></code>", page)

    def test_blocked_payload_is_escaped_everywhere_it_is_rendered(self):
        response = self.client.get("/search?q=%3Cb%3E../../etc/passwd%3C/b%3E")
        blocked_page = response.data.decode("utf-8", errors="replace")

        self.assertEqual(response.status_code, 403)
        self.assertIn("&lt;b&gt;../../etc/passwd&lt;/b&gt;", blocked_page)
        self.assertNotIn("<span style=\"color:var(--amber)\"><b>../../etc/passwd</b></span>", blocked_page)

        dashboard = self.client.get("/dashboard").data.decode("utf-8", errors="replace")
        self.assertIn("&lt;b&gt;../../etc/passwd&lt;/b&gt;", dashboard)
        self.assertNotIn("<code><b>../../etc/passwd</b></code>", dashboard)

        logs = self.client.get("/logs").data.decode("utf-8", errors="replace")
        self.assertIn("&lt;b&gt;../../etc/passwd&lt;/b&gt;", logs)
        self.assertNotIn("<code><b>../../etc/passwd</b></code>", logs)

        feed = self.client.get("/api/live-feed?limit=1").get_json()
        self.assertEqual(feed["items"][0]["payload"], "&lt;b&gt;../../etc/passwd&lt;/b&gt;")

    def test_failed_login_attempts_are_counted_as_allowed_requests(self):
        token = self._get_login_token()

        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "admin",
                "password": "wrongpass",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(waf_app.allowed_log), 1)
        self.assertEqual(waf_app.allowed_log[0]["endpoint"], "/login")


if __name__ == "__main__":
    unittest.main()
