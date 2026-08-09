import unittest

from config import vuln_app
from models.user_model import User


class DebugEndpointTest(unittest.TestCase):
    def test_debug_endpoint_is_not_registered(self):
        registered_routes = {rule.rule for rule in vuln_app.app.url_map.iter_rules()}

        self.assertNotIn('/users/v1/_debug', registered_routes)
        self.assertFalse(hasattr(User, 'json_debug'))

    def test_user_list_returns_only_public_profile_fields(self):
        user = User('name1', 'pass1', 'mail1@mail.com', admin=True)

        # ASVS 14.2.6: return only data required by this public endpoint.
        self.assertEqual(user.json(), {
            'username': 'name1',
            'email': 'mail1@mail.com',
        })


if __name__ == '__main__':
    unittest.main()
