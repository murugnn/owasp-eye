const jwt = require('jsonwebtoken');

// Signing JWT with empty secret and none algorithm
const token = jwt.sign({ userId: 123 }, '', { algorithm: 'none' });
