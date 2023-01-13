# Ref: https://gist.github.com/minrk/fd80a2a1fb226d1af9b9e77669815a59
"""Main module."""
from hashlib import sha256
import json
import uuid, os

from tornado import web
from tornado.httputil import url_concat
from traitlets import Dict

from jupyterhub.handlers.base import BaseHandler
from jupyterhub.services.auth import HubAuthenticated, HubAuth

from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join, maybe_future

class UserTokenHandler(HubAuthenticated, web.RequestHandler):                
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

class UserTokenAuthenticator(Authenticator):

    def get_handlers(self, app):
        """Register our extra handler for one-time token requests"""
        return [("/api/ott", UserTokenHandler)]

    def authenticate(self, handler, data=None):
        """Authenticate is called by `.login_user`,
        This is called both for normal logins and for one-time login requests
        """
        token = handler.get_argument("onetimetoken", None)
        if token:
            # called during the onetimetoken request
            auth = HubAuth(api_token=os.environ['JUPYTERHUB_API_TOKEN'], cache_max_age=60)
            return auth.user_from_token(token)
            # return self.check_one_time_token(token)
        else:
            # a normal login
            return super().authenticate(handler, data)

class OneTimeTokenHandler(HubAuthenticated, BaseHandler):
    
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
        token = self.authenticator.issue_one_time_token(self.current_user)
        self.set_header("Content-Type", "application/json")
        otp_url = url_concat(
            url_path_join(self.hub.base_url, "api/onetimetoken"),
            {"onetimetoken": token},
        )
        self.write(json.dumps({"token": token, "url": otp_url}))


class OneTimeAuthenticator(Authenticator):

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

    def check_one_time_token(self, token):
        """Consume one-time token and return user if found
        Looks up hashed token in the one-time-tokens dict
        """
        htoken = self._hash_token(token)
        # consume one-time token, return user if found,
        # None otherwise
        username = self.one_time_tokens.pop(htoken, None)
        return username

    def authenticate(self, handler, data=None):
        """Authenticate is called by `.login_user`,
        This is called both for normal logins and for one-time login requests
        """
        token = handler.get_argument("onetimetoken", None)
        if token:
            # called during the onetimetoken request
            return self.check_one_time_token(token)
        else:
            # a normal login
            return super().authenticate(handler, data)
