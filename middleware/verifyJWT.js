const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const client = jwksClient({
  jwksUri: process.env.JWKS_URI,
});

function getPublicKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function verifyJWT(req, res, next) {
  try {
    const token = req.headers.authorization.match(/Bearer (.+)/)[1];
    const options = {
      algorithms: ["RS256"],
      issuer: process.env.COGNITO_ISSUER,
    };

    jwt.verify(token, getPublicKey, options, function (err, verifiedToken) {
      if (err || verifiedToken.token_use !== "access") {
        console.error(err);
        next({ code: 401, message: "Unauthorized" });
        return;
      }

      req.jwt = verifiedToken;
      console.log(req.jwt);
      next();
    });
  } catch (err) {
    console.error(err);
    next({ code: 401, message: "Unauthorized" });
  }
}

module.exports = verifyJWT;
