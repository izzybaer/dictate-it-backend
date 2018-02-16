import mongoose from 'mongoose';
mongoose.Promise = Promise;

import {randomBytes} from 'crypto';
import createError from 'http-errors';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';

import * as util from '../lib/util';

const userSchema = new mongoose.Schema({
  username: {type: String, required: true, unique: true},
  displayName: {type: String, required: true, unique: true},
  passwordHash: {type: String},
  tokenSeed: {type: String},
  tokenExpire: {type: Number, default: 0},
});

userSchema.methods.passwordHashCompare = function(password) {
  console.log('passwordHashCompare');
  util.devLog('__password__: ', password);

  return bcrypt.compare(password, this.passwordHash)
    .then(success => {
      if(!success)
        throw createError(401, '__AUTH_ERROR__: wrong password (userSchema.methods.passwordHashCompare)');
      return this;
    });
};

userSchema.methods.tokenCreate = function() {
  this.tokenSeed = randomBytes(32).toString('base64');
  this.tokenExpire = Date.now() + 86400000;
  return this.save()
    .then(user => jwt.sign({tokenSeed: this.tokenSeed}, process.env.SECRET))
    .then(token => token);
};

userSchema.methods.logout = function() {
  this.tokenSeed = undefined;
  return this.save();
};

const User = mongoose.model('user', userSchema);

User.createFromSignup = user => {
  if(!user.username || !user.displayName || !user.password) {
    util.securityWarning('clientside validation bypassed', 'a field is missing', user, 'User.createFromSignup', null);
    return Promise.reject(createError(400, '__AUTH_ERROR__: missing fields for new user'));
  }

  let {password} = user;
  user = {
      ...user,
      password: undefined, // remove password from user to be replaced with passwordHash
  }

  return bcrypt.hash(password, 1)
    .then(passwordHash => {
        let data = {
            ...user,
            passwordHash,
        }
        return new User(data).save();
    });
};

User.fromToken = token => 
  util.promisify(jwt.verify)(token, process.env.SECRET)
    .then(({tokenSeed}) => User.findOne({tokenSeed}))
    .then(user => {
        if(!user)
          throw createError(401, '__AUTH_ERROR__: user not found')
        return user;
    });

export default User;