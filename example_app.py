try:
    import ruamel.yaml as yaml
    with open('secret.yml', 'r') as f:
        secret = yaml.safe_load(f)
except ImportError as err:
    raise ImportError(
'''
You need ruamel.yaml to run the example, \
and also create a valid secret.yml file.
''') from err

except FileNotFoundError as err:
    raise FileNotFoundError(
'''
I HAVE NO FILE AND I MUST SCREAM:
please create a valid secret.yml file \
or provide args to KeycloakAuthenticator \
directly (see source code)
''') from err

# Example:
# auth = KeycloakAuthenticator(
#     app,
#     keycloak_server_url="http://172.17.0.1:8080", # Where Keycloak server is running (here, in a docker container)
#     client_id="name-of-client", # Must be added in Keycloak server
#     realm_name="name-of-realm", # Don't use "master", create a new realm in Keycloak
#     client_secret_key="EuFZ....", # Secret generated from inside Keycloak
#     redirect_url='http://0.0.0.0:8090/' # Where to go back after login is completed
# )

import sanic
from sanic import Sanic
from sanic.log import logger
from sanic.response import json, text, redirect
from sanicloak import KeycloakAuthenticator

app = Sanic('Keycloak-client')
try:

    auth = KeycloakAuthenticator(
        app,
        **secret
    )
except TypeError as err:
    raise TypeError(
'''
Your secret.yml file must follow the following key/values scheme (replace values appropriately, of course):
keycloak_server_url: "http://172.17.0.1:8080"
client_id: "name-of-your-client"
realm_name: "name-of-tour-realm"
client_secret_key: "EuFZ... your client secret"
redirect_url: "http://0.0.0.0:8090/some-redirect-url"
''') from err


@app.route('/')
@auth.protected()
async def login(request):
    logger.info('> Main page handler')
    return json({'fooooo': 'bar'})


@app.get('/logout')
@auth.protected()
async def secret(request):
    logger.info('> Logout page handler')
    logger.info(' * Logging out')
    auth.keycloak_client.logout(request.ctx.token['refresh_token'])
    return redirect(auth.keycloak_login_url)


@app.get('/index')
@auth.protected()
async def secret(request):
    logger.info('> Index page handler')

    return json(request.ctx.identity_token)


@app.get('/index2')
async def secret(request):
    logger.info('> Unprotected Index page handler')

    return text('not protected')


@app.get('/only_admin')
@auth.protected(roles=['xxx'])
async def secret(request):
    logger.info('> Only admin page handler')

    return text('Only admin')

def run():
    app.run(
        host='0.0.0.0',
        port=8090,
        debug=True)

if __name__ == '__main__':
    run()
