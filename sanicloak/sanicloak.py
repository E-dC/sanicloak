from typing import List, Any, Dict, Tuple, Union, Set, Optional
from inspect import isawaitable
from functools import wraps
from urllib3.util import parse_url

import sanic
from sanic.log import logger
from sanic.response import redirect
from sanic.exceptions import InvalidUsage, Forbidden, ServerError

import keycloak
from keycloak import KeycloakOpenID, KeycloakGetError


class KeycloakAuthenticator(object):

    def __init__(
            self,
            app: sanic.Sanic,
            redirect_url: str,
            keycloak_server_url: str,
            client_id: str,
            realm_name: str,
            client_secret_key: str = None,
            verify: bool = True,
            custom_headers: Optional[Dict[Any, Any]] = None,
            proxies: Optional[Dict[Any, Any]] = None):

        self.steps_pre_handler = [
            self.retrieve_token,
            self.validate_token,
            self.redirect_to_origin
        ]

        self.keycloak_client = KeycloakOpenID(
            server_url=keycloak_server_url,
            client_id=client_id,
            realm_name=realm_name,
            client_secret_key=client_secret_key,
            verify=verify,
            custom_headers=custom_headers,
            proxies=proxies
        )

        self.redirect_url = redirect_url
        self.keycloak_login_url = self.keycloak_client.auth_url(self.redirect_url)
        self.app = app

    async def get_token_from_code(self, request: sanic.Request) -> Dict[str, Any]:
        """Exchange a Keycloak authorization code for access and refresh tokens"""

        try:
            code = request.args['code'][0]
        except KeyError:
            logger.debug('Not logged in')
            return False

        try:
            token = self.keycloak_client.token(
                grant_type=['authorization_code'],
                code=code,
                redirect_uri=self.redirect_url)
        except keycloak.KeycloakGetError:
            logger.error('Invalid code')
            raise InvalidUsage(
                f"The authorization_code passed is invalid={code}"
            )
        return token

    async def clear_cookies(
            self, response: sanic.HTTPResponse, *cookies: str) -> sanic.Sanic:
        """Remove cookies from response"""

        for cookie in cookies:
            try:
                del(response.cookies[cookie])
            except KeyError:
                pass
        return response

    async def set_cookies(
            self,
            response: sanic.HTTPResponse,
            httponly: bool = True,
            secure: bool = False,
            max_age: int = 3600,
            **cookies: Union[bool, int]) -> sanic.HTTPResponse:
        """Set cookies in response"""

        for cname, cvalue in cookies.items():
            response.cookies[cname] = cvalue
            response.cookies[cname]['httponly'] = httponly
            response.cookies[cname]['secure'] = secure
            response.cookies[cname]['max-age'] = max_age

        return response

    async def add_requested_url(
            self,
            response: sanic.HTTPResponse,
            requested_url: str) -> sanic.HTTPResponse:
        """ Add a requested_url cookie so that we can redirect towards the page
            originally requested by the user
        """

        if not response.cookies.get('requested_url'):
            x = parse_url(requested_url)
            requested_url = f"{x.scheme}://{x.netloc}{x.path}"
            response = await self.set_cookies(
                response, max_age=30, requested_url=requested_url)
        return response

    async def check_requested_url(
            self, requested_url: str, current_request_url: str) -> bool:
        """Ensure the requested_url value does not lead outside the app routes"""

        try:
            assert requested_url is not None
            assert requested_url not in [
                current_request_url, current_request_url.rstrip('/')
            ]
        except AssertionError:
            return False

        x = parse_url(requested_url)
        base = f'{x.scheme}://{x.netloc}'
        try:
            assert base == self.app.serve_location
            assert x.path.lstrip('/') in [
                r.path for r in self.app.router.routes
            ]
            return True
        except AssertionError:
            raise ServerError

    async def retrieve_token(
            self,
            request: sanic.Request) -> Union[sanic.Request, sanic.HTTPResponse]:
        """Ensure appropriate tokens are present before a request reach its handler"""

        logger.debug('> Retrieve token (request)')

        try:
            logger.debug(' * Checking for a valid KC token in cookies')
            token = {
                'access_token': request.cookies['kc-access'],
                'refresh_token': request.cookies['kc-refresh'],
            }
            request.ctx.token = token
            logger.debug(' * Found KC token in cookies')
            return request

        except KeyError:
            logger.debug(
                ' * No KC token found, checking for an authorization code in args')
            token = await self.get_token_from_code(request)
            if token:
                logger.debug(
                    ' * Authorization code found and exchanged for a token')
                request.ctx.token = token
                return request

        logger.debug(' * Invalid or absent authorization code, redirecting to KC login')
        response = redirect(self.keycloak_login_url)
        response = await self.add_requested_url(response, request.url)
        return response

    async def validate_token(
            self,
            request: sanic.Request) -> Union[sanic.Request, sanic.HTTPResponse]:
        """ Ensure access token is valid before a request reach its handler,
            refresh if necessary"""

        logger.debug('> Validate token (request)')

        logger.debug(' * Checking validity of KC access token (introspection)')
        introspected = self.keycloak_client.introspect(
            request.ctx.token['access_token'])
        if introspected['active']:
            logger.debug(' * Access token is valid')
            request.ctx.identity_token = introspected
            return request

        try:
            logger.debug(' * Invalid or expired access token, attempting to refresh')
            token = self.keycloak_client.refresh_token(
                request.ctx.token['refresh_token'])
            introspected = self.keycloak_client.introspect(
                request.ctx.token['access_token'])

            if introspected['active']:
                logger.debug(' * Access token refreshed')
                request.ctx.token = token
                request.ctx.identity_token = introspected
                return request
            raise KeycloakGetError

        except KeycloakGetError:
            logger.debug(' * Refresh attempt failed')
            logger.debug(' * Clearing KC cookies and redirecting to KC login')
            response = await self.clear_cookies(
                redirect(self.keycloak_login_url), 'kc-access', 'kc-refresh')

            response = await self.add_requested_url(response, request.url)
            return response

    async def redirect_to_origin(
            self,
            request: sanic.Request) -> Union[sanic.Request, sanic.HTTPResponse]:
        """ Redirect to the URL originally requested by the user, if it is different
            from self.redirect_url"""

        logger.debug(
            '> Ensure route used is the one originally requested (request)')

        logger.debug(
            ' * Check whether a redirect to originally requested url is needed')
        requested_url = request.cookies.get('requested_url')
        redirect_needed = await self.check_requested_url(
            requested_url, request.url)

        if redirect_needed:
            logger.debug(f' * Redirection to {requested_url} necessary')
            response = await self.clear_cookies(
                redirect(requested_url), 'requested_url')
            response = await self.set_keycloak_cookies(request, response)
            return response
        logger.debug(' * No redirection needed')
        return request

    async def set_keycloak_cookies(
            self,
            request: sanic.Request,
            response: sanic.HTTPResponse) -> sanic.HTTPResponse:
        """ Set Keycloak cookies in response so that user does not need to login
            again after next request
        """

        logger.debug('> Set Keycloak cookies (response)')

        try:
            assert request.ctx.protected is True
        except AttributeError:
            return response

        logger.debug(' * Checking whether tokens are in request context')
        try:
            context_token = request.ctx.token
            assert 'access_token' in context_token
            assert 'refresh_token' in context_token
        except AttributeError:
            raise ServerError('No token found in request context')
        except AssertionError:
            raise ServerError('Token found in request context is invalid')

        logger.debug(
            ' * Check if KC cookies exist: they will be set if absent or stale')
        cookie_access_token = request.cookies.get('kc-access')
        cookie_refresh_token = request.cookies.get('kc-refresh')

        try:
            assert cookie_access_token
            assert cookie_refresh_token
            assert cookie_access_token == context_token['access_token']
            assert cookie_refresh_token == context_token['refresh_token']
        except AssertionError:
            logger.debug(' * Setting KC cookies')
            response = await self.set_cookies(
                response,
                **{
                    'kc-access': context_token['access_token'],
                    'kc-refresh': context_token['refresh_token']
                }
            )
        return response

    async def check_roles(
            self,
            request: sanic.Request,
            roles: Union[List, Set, Tuple]) -> sanic.Request:
        """ Check if the user has an authorized role, by checking
            the user's identity token
        """

        try:
            user_roles = set(request.ctx.identity_token['roles'])
        except KeyError:
            user_roles = set(request.ctx.identity_token['realm_access']['roles'])

        if not user_roles.intersection(set(roles)):
            raise Forbidden('Restricted access')

        return request

    def protected(self, maybe_func=None, *, roles=None):
        """Decorator to use so that app routes are protected"""
        def decorator(handler):
            @wraps(handler)
            async def decorated_function(request, *args, **kwargs):

                request.ctx.protected = True
                for func in self.steps_pre_handler:
                    request = await func(request)
                    if not isinstance(request, sanic.Request):
                        return request

                if roles:
                    request = await self.check_roles(request, roles)

                response = handler(request, *args, **kwargs)

                if isawaitable(response):
                    response = await response

                response = await self.set_keycloak_cookies(request, response)

                return response

            return decorated_function

        return decorator(maybe_func) if maybe_func else decorator
