const express = require('express');
const session = require('express-session');
const AWS = require('aws-sdk');
const { Issuer, generators } = require('openid-client');

const app = express();

const AWS_REGION = process.env.REGION;
const SECRET_ID = process.env.SECRET_ID;

const COGNITO_ISSUER_URL = process.env.COGNITO_ISSUER_URL;
const SERVICE_ENDPOINT = process.env.SERVICE_ENDPOINT;
const CALLBACK_URI = process.env.CALLBACK_URI;
const LOGOUT_URI = process.env.LOGOUT_URI;

const secretsManager = new AWS.SecretsManager({ region: AWS_REGION });

async function getCognitoSecrets() {
    const data = await secretsManager.getSecretValue({
        SecretId: SECRET_ID
    }).promise();

    const secret = JSON.parse(data.SecretString);
    return secret;
}

let client_id;
let client_secret;
let session_secret;

getCognitoSecrets().then((creds) => {
    client_id = creds.client_id;
    client_secret = creds.client_secret;
    session_secret = creds.session_secret;
});

let client;

async function initializeClient() {
    const issuer = await Issuer.discover(COGNITO_ISSUER_URL);
    client = new issuer.Client({
        client_id: client_id,
        client_secret: client_secret,
        redirect_uris: [CALLBACK_URI],
        response_types: ['code']
    });
};

app.set('view engine', 'ejs');
initializeClient().catch(console.error);

app.use(session({
    secret: session_secret,
    resave: false,
    saveUninitialized: false
}));

const checkAuth = (req, res, next) => {
    console.log(req.session.userInfo);
    if (!req.session.userInfo) {
        req.isAuthenticated = false;
    } else {
        req.isAuthenticated = true;
    }
    next();
};

app.get('/', checkAuth, (req, res) => {
    res.render('home', {
        isAuthenticated: req.isAuthenticated,
        userInfo: req.session.userInfo,
        accessToken: req.session.accessToken,
        gatewayEndpoint: SERVICE_ENDPOINT
    });
});

app.get('/login', (req, res) => {
    const nonce = generators.nonce();
    const state = generators.state();

    req.session.nonce = nonce;
    req.session.state = state;

    const authUrl = client.authorizationUrl({
        scope: 'email openid phone',
        state: state,
        nonce: nonce,
    });

    res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
    try {
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            CALLBACK_URI,
            params,
            {
                nonce: req.session.nonce,
                state: req.session.state
            }
        );

        const userInfo = await client.userinfo(tokenSet.access_token);
        
        req.session.userInfo = userInfo;
        req.session.accessToken = tokenSet.access_token; // this is actually insane but nvm

        res.redirect('/');
    } catch (err) {
        console.error('Callback error:', err);
        res.redirect('/');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    const logoutUrl = LOGOUT_URI;
    res.redirect(logoutUrl);
});

app.listen(3000, '0.0.0.0', () => {
    console.log(`Server is running`);
});

// const express = require('express')
// const app = express()
// const port = 3000

// app.get('/', (req, res) => {
//   res.send('Hello World!')
// })

// app.listen(port, '0.0.0.0', () => {
//   console.log(`Example app listening on port ${port}`)
// })