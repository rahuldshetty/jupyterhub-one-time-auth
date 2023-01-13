"""Main module."""
from hashlib import sha256
import json
import uuid

from tornado import web
from tornado.httputil import url_concat
from traitlets import Dict

from jupyterhub.handlers.base import BaseHandler
from jupyterhub.services.auth import HubAuthenticated

from jupyterhub.auth import DummyAuthenticator
from jupyterhub.utils import url_path_join, maybe_future

class OneTimeTokenHandler(HubAuthenticated, web.RequestHandler):
    
    async def get(self):
        """GET /api/onetimetoken?onetimetoken=...
        logs in users with a one-time token.
        Once used, the token cannot be used again.
        """
        token = self.get_argument("onetimetoken")
        if not token:
            raise web.HTTPError(400, "No token!")
        user = await maybe_future(self.login_user())
        if user:
            self.redirect(self.get_next_url(user))
        else:
            raise web.HTTPError(
                403, "This one-time token is not valid. Maybe it has already been used?"
            )

    @web.authenticated
    def post(self):
        """POST /api/onetimetoken
        creates a new one-time use token
        replies with JSON including the token itself
        and the URL required to login with it.
        The URL will typically only be a url *path*,
        excluding the public host of jupyterhub,
        so the public host will need to be added for links.
        """
        print("test123...")
        token = self.authenticator.issue_one_time_token(self.current_user)
        self.set_header("Content-Type", "application/json")
        otp_url = url_concat(
            url_path_join(self.hub.base_url, "api/onetimetoken"),
            {"onetimetoken": token},
        )
        self.write(json.dumps({"token": token, "url": otp_url}))


class OneTimeAuthenticator(DummyAuthenticator):

    one_time_tokens = Dict()

    def get_handlers(self, app):
        """Register our extra handler for one-time token requests"""
        return [("/api/onetimetoken", OneTimeTokenHandler)]

    def _hash_token(self, token):
        """Compute the hash of a token"""
        return sha256(token.encode("ascii")).hexdigest()

    def issue_one_time_token(self, user):
        """Issue one-time token for a user
        Stores the hashed token with a reference to the user,
        returning the token.
        """
        token = uuid.uuid4().hex
        hashed_token = self._hash_token(token)
        self.one_time_tokens[hashed_token] = user.name
        return token

    def check_one_time_token(self, token, url):
        """Consume one-time token and return user if found
        Looks up hashed token in the one-time-tokens dict
        """
        htoken = self._hash_token(token)
        # consume one-time token, return user if found,
        # None otherwise
        username = self.one_time_tokens.pop(htoken, None)
        return {
            "name": username,
            "auth_state": {
                "url": url
            }
        }

    def pre_spawn_start(self, user, spawner):
        """Pass url to spawner via arguments variable"""
        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        # set default url
        if "url" not in auth_state:
            default_url = "tree"
        else:
            default_url = auth_state['url']
        
        spawner.default_url = default_url

    def authenticate(self, handler, data=None):
        """Authenticate is called by `.login_user`,
        This is called both for normal logins and for one-time login requests
        """
        token = handler.get_argument("onetimetoken", None)
        url = handler.get_argument("url", None)
        if url == None:
            url = "tree"
        if token:
            # called during the onetimetoken request
            return self.check_one_time_token(token, url)
        else:
            # a normal login
            return super().authenticate(handler, data)
