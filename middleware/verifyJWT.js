const jwks = require("../jwks.json");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

const keys = {};
for (let k of jwks.keys) {
  keys[k.kid] = k;
}

function verifyJWT(token) {
  try {
    const decodedJwt = jwt.decode(token, { complete: true });
    const pem = jwkToPem(keys[decodedJwt.header.kid]);
    jwt.verify(token, pem, { algorithms: ["RS256"] }, function (
      err,
      verifiedToken
    ) {
      if (err) throw err;
      else console.log(verifiedToken);
    });
  } catch (err) {
    console.log("MyError");
    console.error(err);
  }
}

module.exports = verifyJWT;
