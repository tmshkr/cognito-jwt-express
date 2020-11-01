const jwks = require("../jwks.json");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

const keys = {};
for (let k of jwks.keys) {
  keys[k.kid] = k;
}

function verifyJWT(req, res, next) {
  try {
    const token = req.headers.authorization.match(/Bearer (.+)/)[1];
    const decodedJwt = jwt.decode(token, { complete: true });
    const { token_use, iss } = decodedJwt.payload;
    if (iss !== process.env.COGNITO_ISSUER) throw new Error("Invalid issuer");
    if (token_use !== "access")
      throw new Error("Please provide an access token");

    const pem = jwkToPem(keys[decodedJwt.header.kid]);
    req.jwt = jwt.verify(token, pem, { algorithms: ["RS256"] });
    console.log(req.jwt);
    next();
  } catch (err) {
    console.error(err);
    next({ code: 401, message: "Unauthorized" });
  }
}

module.exports = verifyJWT;
