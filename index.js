const bodyParser = require('body-parser');
const express = require('express');
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

app.get('/Users', function (req, res) {
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

app.put('/Users/:id/ChangeRole', function (req, res) {
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
