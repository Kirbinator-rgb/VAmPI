import unittest
from unittest.mock import patch

from config import vuln_app
from api_views.users import register_user


class MassAssignmentTest(unittest.TestCase):
    def register(self, payload):
        with vuln_app.app.test_request_context(
                '/users/v1/register', method='POST', json=payload):
            with patch('api_views.users.User') as user_model, \
                    patch('api_views.users.db') as database:
                user_model.query.filter_by.return_value.first.return_value = None
                response = register_user()
        return response, user_model, database

    def test_registration_rejects_admin_property(self):
        response, user_model, database = self.register({
            'username': 'attacker',
            'password': 'pass1',
            'email': 'attacker@example.com',
            'admin': True,
        })

        self.assertEqual(response.status_code, 400)
        user_model.assert_not_called()
        database.session.add.assert_not_called()

    def test_registration_uses_server_default_privileges(self):
        response, user_model, _ = self.register({
            'username': 'member',
            'password': 'pass1',
            'email': 'member@example.com',
        })

        self.assertEqual(response.status_code, 200)
        user_model.assert_called_once_with(
            username='member', password='pass1', email='member@example.com')


if __name__ == '__main__':
    unittest.main()
