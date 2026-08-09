import unittest
from unittest.mock import patch

from config import vuln_app
from models.user_model import User


class UsernameLookupTest(unittest.TestCase):
    def test_username_lookup_uses_orm_filter(self):
        injection = "anythingRandom' or '1'='1"
        expected_user = object()

        with vuln_app.app.app_context(), patch.object(User, 'query') as query:
            query.filter_by.return_value.first.return_value = expected_user

            result = User.get_user(injection)

        self.assertIs(result, expected_user)
        query.filter_by.assert_called_once_with(username=injection)


if __name__ == '__main__':
    unittest.main()
