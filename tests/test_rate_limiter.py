import unittest

from flask import Flask

from rate_limiter import SlidingWindowRateLimiter, configure_rate_limiting


class MutableClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class RateLimiterTest(unittest.TestCase):
    def test_requests_are_limited_until_window_expires(self):
        clock = MutableClock()
        limiter = SlidingWindowRateLimiter(2, 60, clock=clock)

        self.assertEqual(limiter.check('client'), (True, 0))
        self.assertEqual(limiter.check('client'), (True, 0))
        allowed, retry_after = limiter.check('client')
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)

        clock.now = 60
        self.assertEqual(limiter.check('client'), (True, 0))

    def test_flask_returns_429_and_retry_after(self):
        app = Flask(__name__)
        limiter = SlidingWindowRateLimiter(2, 60, clock=lambda: 0)
        configure_rate_limiting(
            app, limiter, limited_routes={('POST', '/users/v1/login')})

        @app.post('/users/v1/login')
        def login():
            return {'status': 'ok'}

        client = app.test_client()
        self.assertEqual(client.post('/users/v1/login').status_code, 200)
        self.assertEqual(client.post('/users/v1/login').status_code, 200)
        response = client.post('/users/v1/login')

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers['Retry-After'], '60')

    def test_unrelated_routes_are_not_rate_limited(self):
        app = Flask(__name__)
        limiter = SlidingWindowRateLimiter(1, 60, clock=lambda: 0)
        configure_rate_limiting(app, limiter)

        @app.get('/users/v1')
        def users():
            return {'status': 'ok'}

        client = app.test_client()
        self.assertEqual(client.get('/users/v1').status_code, 200)
        self.assertEqual(client.get('/users/v1').status_code, 200)


if __name__ == '__main__':
    unittest.main()
