import sanic
from sanic.log import logger
from sanic.response import redirect
from sanic.exceptions import InvalidUsage, Unauthorized, Forbidden, ServerError
import keycloak
from keycloak import KeycloakOpenID, KeycloakGetError

from urllib3.util import parse_url
from inspect import isawaitable
from functools import wraps

class KeycloakAuthenticator(object):


    def __init__(
        self,
        app,
        keycloak_server_url,
        client_id,
        realm_name,
        client_secret_key,
        redirect_url):

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
            verify=True
        )

        self.redirect_url = redirect_url

        self.keycloak_login_url = self.keycloak_client.auth_url(self.redirect_url)

        self.app = app

    async def get_token_from_code(self, request):
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

    async def clear_cookies(self, response, *cookies):
        for cookie in cookies:
            try:
                del(response.cookies[cookie])
            except KeyError:
                pass
        return response

    async def set_cookies(
        self,
        response,
        httponly=True,
        secure=False,
        max_age=3600,
        **cookies):
        for cname, cvalue in cookies.items():
            response.cookies[cname] = cvalue
            response.cookies[cname]['httponly'] = httponly
            response.cookies[cname]['secure'] = secure
            response.cookies[cname]['max-age'] = max_age

        return response


    async def add_requested_url(self, response, requested_url):
        if not response.cookies.get('requested_url'):
            x = parse_url(requested_url)
            requested_url = f"{x.scheme}://{x.netloc}{x.path}"
            response = await self.set_cookies(
                response, max_age=30, requested_url=requested_url)
        return response

    async def check_requested_url(self, requested_url):
        x = parse_url(requested_url)
        base = f'{x.scheme}://{x.netloc}'
        try:
            assert base == self.app.serve_location
            assert x.path.lstrip('/') in [r.path for r in self.app.router.routes]
            return True
        except AssertionError:
            raise ServerError

    async def retrieve_token(self, request):
        logger.info('> Retrieve token (request)')

        try:
            logger.info(' * Checking for a valid KC token in cookies')
            token = {
                'access_token': request.cookies['kc-access'],
                'refresh_token': request.cookies['kc-refresh'],
            }
            request.ctx.token = token
            logger.info(' * Found KC token in cookies')
            return request

        except KeyError:
            logger.info(' * No KC token found, checking for an authorization code in args')
            token = await self.get_token_from_code(request)
            if token:
                logger.info(' * Authorization code found and exchanged for a token')
                request.ctx.token = token
                return request

        logger.warning(' * Invalid or absent authorization code, redirecting to KC login')
        response = redirect(self.keycloak_login_url)
        response = await self.add_requested_url(response, request.url)
        return response

    async def validate_token(self, request):
        logger.info('> Validate token (request)')

        logger.info(' * Checking validity of KC access token (introspection)')
        introspected = self.keycloak_client.introspect(
            request.ctx.token['access_token'])
        if introspected['active']:
            logger.info(' * Access token is valid')
            request.ctx.identity_token = introspected
            return request

        try:
            logger.info(' * Invalid or expired access token, attempting to refresh')
            token = self.keycloak_client.refresh_token(request.ctx.token['refresh_token'])

            introspected = self.keycloak_client.introspect(request.ctx.token['access_token'])
            if introspected['active']:
                logger.info(' * Access token refreshed')
                request.ctx.token = token
                request.ctx.identity_token = introspected
                return request
            raise KeycloakGetError

        except KeycloakGetError:
            logger.warning(' * Refresh attempt failed')
            logger.warning(' * Clearing KC cookies and redirecting to KC login')
            response = await self.clear_cookies(
                redirect(self.keycloak_login_url), 'kc-access', 'kc-refresh')

            response = await self.add_requested_url(response, request.url)
            return response

    async def redirect_to_origin(self, request):
        logger.info('> Ensure route used is the one originally requested (request)')

        logger.info(
            ' * Checking whether a redirection to originally requested url is necessary')
        requested_url = request.cookies.get('requested_url')
        if requested_url and request.url not in [requested_url, requested_url.rstrip('/')] :
            await self.check_requested_url(requested_url)
            logger.info(f' * Redirection to {requested_url} necessary')
            response = await self.clear_cookies(
                redirect(requested_url), 'requested_url')
            response = await self.set_keycloak_cookies(request, response)
            return response
        logger.info(' * No redirection needed')
        return request


    async def set_keycloak_cookies(self, request, response):
        logger.info('> Set Keycloak cookies (response)')

        try:
            assert request.ctx.protected is True
        except AttributeError:
            return response

        logger.info(' * Checking whether tokens are in request context')
        try:
            context_token = request.ctx.token
            assert 'access_token' in context_token
            assert 'refresh_token' in context_token
        except:
            raise ServerError('No token found in request context')

        logger.info(' * Checking if KC cookies exist: they will be set if they\'re absent or stale')
        cookie_access_token = request.cookies.get('kc-access')
        cookie_refresh_token = request.cookies.get('kc-refresh')

        logger.debug(f"context access token:\n{context_token['access_token']}")
        logger.debug(f"context refresh token:\n{context_token['refresh_token']}")
        logger.debug(f"cookie access token:\n{cookie_access_token}")
        logger.debug(f"cookie refresh token:\n{cookie_refresh_token}")

        if (not cookie_access_token
            or not cookie_refresh_token
            or cookie_access_token != context_token['access_token']
            or cookie_refresh_token != context_token['refresh_token']):

            logger.info(' * Setting KC cookies')
            response = await self.set_cookies(
                response,
                **{
                    'kc-access': context_token['access_token'],
                    'kc-refresh': context_token['refresh_token']
                }
            )
        return response


    async def check_roles(self, request, roles):
        try:
            user_roles = set(request.ctx.identity_token['roles'])
        except KeyError:
            user_roles = set(request.ctx.identity_token['realm_access']['roles'])

        if not user_roles.intersection(set(roles)):
            raise Forbidden('Restricted access')

        return request

    def protected(self, maybe_func=None, *, roles=None):
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

