const jwks = require("./jwks.json");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

const keys = {};
for (let k of jwks.keys) {
  keys[k.kid] = k;
}

const decodedJwt = jwt.decode(token, { complete: true });

const pem = jwkToPem(keys[decodedJwt.header.kid]);
jwt.verify(token, pem, { algorithms: ["RS256"] }, function (err, decodedToken) {
  if (err) {
    console.error(err);
    return;
  }
  console.log(decodedToken);
});
