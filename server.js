const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const server = express();
const verifyJWT = require("./middleware/verifyJWT");

server.use(helmet());
server.use(cors());
server.use(express.json());

server.get("/", (req, res) => res.json({ server: "up" }));

/* AUTHENTICATED ROUTES */

server.get("/authenticated", verifyJWT, (req, res) =>
  res.json({ authenticated: true })
);

server.use(errorHandler);

module.exports = server;

function errorHandler(err, req, res, next) {
  res.status(err.code).json({ message: err.message });
}
