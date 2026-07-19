// Test fixture for rules/javascript/api-security.yaml
//
// Lines annotated "ruleid" must produce the named finding.
// Lines annotated "ok" must NOT produce it.

const jwt = require("jsonwebtoken");
const cors = require("cors");

const ALLOWED_FIELDS = ["name", "email", "phone"];

// ---------------------------------------------------------------- vulnerable

function readClaims(token) {
  // ruleid: js-jwt-verification-disabled
  return jwt.decode(token);
}

function verifyWithNone(token, key) {
  // ruleid: js-jwt-none-algorithm
  return jwt.verify(token, key, { algorithms: ["HS256", "none"] });
}

async function findUserByEmail(req, res) {
  // ruleid: js-mongo-query-from-request-body
  const user = await User.findOne({ email: req.body.email });
  res.json(user);
}

async function createUser(req, res) {
  // ruleid: js-object-assign-from-request-body
  const user = await User.create(req.body);
  res.json(user);
}

async function updateProfile(req, res, profile) {
  // ruleid: js-object-assign-from-request-body
  Object.assign(profile, req.body);
  await profile.save();
}

function setupCors(app) {
  // ruleid: js-express-cors-wildcard-with-credentials
  app.use(cors({ origin: "*", credentials: true }));
}

// --------------------------------------------------------------------- safe

function verifyToken(token, publicKey) {
  // ok: js-jwt-none-algorithm
  return jwt.verify(token, publicKey, { algorithms: ["RS256"] });
}

async function findUserSafely(req, res) {
  const email = String(req.body.email);
  // ok: js-mongo-query-from-request-body
  const user = await User.findOne({ email: email });
  res.json(user);
}

async function createUserSafely(req, res) {
  const data = {};
  for (const field of ALLOWED_FIELDS) {
    if (req.body[field] !== undefined) data[field] = req.body[field];
  }
  // ok: js-object-assign-from-request-body
  const user = await User.create(data);
  res.json(user);
}

function setupCorsSafely(app) {
  // ok: js-express-cors-wildcard-with-credentials
  app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
}
