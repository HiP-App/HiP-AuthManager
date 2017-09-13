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

function forbidden (message) {
    const error = new Error(
      'permission_denied', { message: message || 'Permission denied' }
    );
    error.statusCode = 403;
    return error;
}

const rolesIdentifier = 'https://hip.cs.upb.de/roles';
const ADMIN = 'Administrator';
const SUPERVISOR = 'Supervisor';

function checkRole (req, res, next) {
    const rolesExist = req.user &&
        req.user[rolesIdentifier] &&
        Array.isArray(req.user[rolesIdentifier]);
    req.user.isAdmin = rolesExist && req.user[rolesIdentifier].includes(ADMIN);
    req.user.isSupervisor = rolesExist && req.user[rolesIdentifier].includes(SUPERVISOR);

    if (req.user.isAdmin || req.user.isSupervisor) {
        next();
    } else {
        next(forbidden());
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

function isAdmin (id, token, cb) {
    const options = {
        url: process.env.MANAGEMENTAUDIENCE + 'users/' + id,
        headers: {
            authorization: 'Bearer ' + token,
            'Content-Type': 'application/json'
        }
    };
    request(options, function (error, response, body) {
        if (body.app_metadata && Array.isArray(body.app_metadata.roles)) {
            cb(body.app_metadata.roles.includes(ADMIN));
        } else {
            cb(false);
        }
    });
}

function changeRole (roles, token, req, res) {
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
}

app.put('/Users/:id/ChangeRole', checkJwt, checkRole, function (req, res, next) {
    const roles = req.body.roles;
    if (roles.includes(ADMIN)) {
        next(forbidden('cannot grant anyone the adminstrator role using this API'));
    } else {
        requestToken(function (token) {
            isAdmin(req.params.id, token, function (admin) {
                if (admin) {
                    changeRole(roles, token, req, res);
                } else {
                    next(forbidden('cannot edit administrators roles using this API'));
                }
            })
        })
    }
});

app.get('/', function (req, res) {
    res.status(200).send('PUT: /Users/:id/ChangeRole, GET: /Users');
});

app.listen(process.env.PORT, function () {
    console.log('HiP-AuthManager running on ' + process.env.PORT)
});
