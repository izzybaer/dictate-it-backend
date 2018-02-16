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
        res.cookie('X-StT-Token', token, { maxAge: 86400000, httpOnly: true, secure: true })
        res.send(token)
    })
    .catch(next);
});

// change a users password
authRouter.put('/auth', bearerAuth, jsonParser, (req, res, next) => {
    let passwords = req.body;
    let requestInfo = {
        headers: req.headers,
        hostname: req.hostname,
        ip: req.ip,
        ips: req.ips,
    }
    console.log('__PUT__: /auth password change');
    util.devLog('full user info: ', req.user);
    console.log('user info: ', {...req.user._doc, passwordHash: undefined, tokenSeed: undefined, tokenExpire: undefined});
    util.devLog('passwords: ', passwords);
    console.log('request info: ', requestInfo);

    // passwords shouldnt be logged here but the data is necessary for the security 
    // so we can see what is being passed in that is bypassing the filter
    if(!passwords.oldPassword || !passwords.newPassword || !passwords.newPassword2) {
        util.securityWarning('clientside validation bypassed', 'a field is missing', passwords, 'authRouter.put /auth', requestInfo)
        return req.user.logout() // destroy session if security has been bypassed
          .then(() => {
              res.set({
                  'Strict-Transport-Security': 'max-age: 10000000000; includeSubDomains',
                  'X-Content-Type-Options': 'nosniff',
                  'X-XSS-Protection': '1; mode=block',
                  'X-Frame-Options': 'DENY',
              })
              res.clearCookie('X-StT-Token')
              res.sendStatus(400)
          })
          .catch(next);
    }
    if(passwords.oldPassword === passwords.newPassword || passwords.oldPassword === passwords.newPassword2) {
        util.securityWarning('clientside validation bypassed', 'old password is equal to new password', passwords, 'authRouter.put /auth', requestInfo);
        return req.user.logout()
          .then(() => {
              res.set({
                  'Strict-Transport-Security': 'max-age: 10000000000; includeSubDomains',
                  'X-Content-Type-Options': 'nosniff',
                  'X-XSS-Protection': '1: mode=block',
                  'X-Frame-Options': 'DENY',
              })
              res.clearCookie('X-StT-Token')
              res.sendStatus(400)
          })
          .catch(next);
    }
    if(passwords.newPassword !== passwords.newPassword2) {
        util.securityWarning('clientside validation bypassed', 'new password 1 and 2 don\'t match', passwords, 'authRouter.put /auth', requestInfo)
        return req.user.logout()
          .then(() => {
              res.set({
                  'Strict-Transport-Security': 'max-age: 10000000000; includeSubDomains',
                  'X-Content-Type-Options': 'nosniff',
                  'X-XSS-Protection': '1; mode=block',
                  'X-Frame-Options': 'DENY',
              })
              res.clearCookie('X-StT-Token')
              res.sendStatus(400)
          })
          .catch(next);
    }
    if(passwords.oldPassword.length < 8 || passwords.newPassword.length < 8) {
        util.securityWarning('clientside validation bypassed', 'password too short', passwords, 'authRouter.put /auth', requestInfo)
        return req.user.logout()
          .then(() => {
              res.set({
                  'Strict-Transport-Security': 'max-age: 10000000000; includeSubDomains',
                  'X-Content-Type-Options': 'nosniff',
                  'X-XSS-Protection': '1; mode=block',
                  'X-Frame-Options': 'DENY',
              })
              res.clearCookie('X-StT-Token')
              res.sendStatus(400)
          })
          .catch(next);
    }

    req.user.passwordHashCompare(passwords.oldPassword)
      .then(user => bcrypt.hash(passwords.newPassword, 1))
      .then(passwordHash => User.findOneAndUpdate({username: req.user.username}, {passwordHash}))
      .then(() => {
          res.set({
              'Strict-Transport-Security': 'max-age: 10000000000; includeSubDomains',
              'X-Content-Type-Options': 'nosniff',
              'X-XSS-Protection': '1; mode=block',
              'X-Frame-Options': 'DENY',
          })
          res.sendStatus(200)
      })
      .catch(next);
});









































export default authRouter;