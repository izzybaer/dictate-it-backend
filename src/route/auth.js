import {Router} from 'express';
import bodyParser from 'body-parser';
import * as bcrypt from 'bcrypt';

import User from '../model/user';
import basicAuth from '../middleware/basic-auth';
import bearerAuth from '../middleware/bearer-auth';
import * as util from '../lib/util';

const jsonParser = bodyParser.json();
const authRouter = new Router();

// register a user
authRouter.post('/auth', jsonParser, (req, res, next) => {
  let user = req.body;
  let requestInfo = {
    headers: req.headers,
    hostname: req.hostname,
    ip: req.ip,
    ips: req.ips,
  };

  console.log('__POST__: /auth register a user');
  util.devLog('full user info: ', user);
  console.log('user info: ', {...user, password: null, password2: null})
  console.log('request info: ', requestInfo);

  if(!user.username || !user.displayName || !user.password) {
      util.securityWarning('clientside validation bypassed', 'a field is missing', user, 'authRouter.post /auth', requestInfo)
      res.sendStatus(400);
  }
  if(!/^[\w]+$/.test(user.displayName)) {
      util.securityWarning('clientside validation bypassed', 'display name has characters that aren\'t allowed', user, 'authRounter.post /auth', requestInfo)
      return res.sendStatus(400);
  }
  if(user.password.length < 8) {
      util.securityWarning('clientside validation bypassed', 'password too short', user, 'authRouter.post /auth', requestInfo)
      return res.sendStatus(400);
  }

  new User.createFromSignup(user)
    .then(user => user.tokenCreate())
    .then(token => {
        res.set({
          'Strict-Transport-Security': 'max-age: 10000000000; includeSubDomains',
          'X-Content-Type-Options': 'nosniff',
          'X-XSS-Protection': '1; mode=block',
          'X-Frame-Options': 'DENY',
        })
        res.cookie("X-StT-Token", token, { maxAge: 86400000, httpOnly: true, secure: true })
        res.send(token);
    })
    .catch(next);
});