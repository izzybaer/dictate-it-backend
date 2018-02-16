require('dotenv').config(); // configuring correct ENV variables
require('./src/lib/assert-env.js'); // make sure all required ENV vars have been defined
require('babel-register'); // ES6
require('./src/main.js');