const bodyParser = require('body-parser');
const express = require('express');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const request = require('request');

require('dotenv').config();

const authOptions = {
    method: 'POST',
    url: 'https://hip.eu.auth0.com/oauth/token',
    headers: { 'content-type': 'application/json' },
    body: `{ "client_id": "${process.env.MANAGEMENTCLIENTID}", "client_secret": "${process.env.MANAGEMENTCLIENTSECRET}", "audience": "${process.env.MANAGEMENTAUDIENCE}", "grant_type":"client_credentials" }`
};

const app = express();

app.use(bodyParser.json());

// Authentication middleware. When used, the
// access token must exist and be verified against
// the Auth0 JSON Web Key Set
const checkJwt = jwt({
  // Dynamically provide a signing key
  // based on the kid in the header and
  // the singing keys provided by the JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${process.env.AUTHORITY}.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
  audience: process.env.AUDIENCE,
  issuer: process.env.AUTHORITY,
  algorithms: ['RS256']
});

const rolesIdentifier = 'https://hip.cs.upb.de/roles';

function checkRole (req, res, next) {
    const rolesExist = req.user &&
        req.user[rolesIdentifier] &&
        Array.isArray(req.user[rolesIdentifier]);
    const validRole = rolesExist && (
        req.user[rolesIdentifier].includes('Administrator') ||
        req.user[rolesIdentifier].includes('Supervisor')
    );
    if (validRole) {
        next();
    } else {
        const error = new Error(
          'permission_denied', { message: 'Permission denied' }
        );
        error.statusCode = 403;
        next(error);
    }
}

// NOTE: Currently, a new token is requested for every API call.
// Not sure if this could cause problems - if yes, save the token and
// re-use until it expires, then request a new one
function requestToken(cb) {
    request(authOptions, function (error, response, body) {
        if (error) throw new Error(error);
        const content = JSON.parse(body);
        cb(content.access_token);
    });
}

app.get('/Users', checkJwt, checkRole, function (req, res) {
    requestToken(function (token) {
        const options = {
            url: process.env.MANAGEMENTAUDIENCE + 'users',
            headers: { authorization: 'Bearer ' + token }
        };
        request(options, function (error, response, body) {
            if (error) {
                console.error(error);
                res.status(response ? response.statusCode : 400).send();
            } else {
                res.append('Content-Type', 'application/json');
                res.status(response.statusCode).send(body);
            }
        });
    });
});

app.put('/Users/:id/ChangeRole', checkJwt, function (req, res) {
    const roles = req.body.roles;
    requestToken(function (token) {
        const options = {
            method: 'PATCH',
            url: process.env.MANAGEMENTAUDIENCE + 'users/' + req.params.id,
            headers: {
                authorization: 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ app_metadata: { roles: roles } })
        };
        request(options, function (error, response, body) {
            if (error) {
                console.error(error);
                res.status(response ? response.statusCode : 400).send();
            } else {
                res.append('Content-Type', 'application/json');
                res.status(response.statusCode).send(body);
            }
        });
    })
});

app.listen(process.env.PORT, function () {
    console.log('HiP-AuthManager running on ' + process.env.PORT)
});
