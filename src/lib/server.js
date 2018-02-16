import cors from 'cors';
import {Server} from 'http';
import morgan from 'morgan';
import express from 'express';
import {randomBytes} from 'crypto';

import * as mongo from './mongo';
import User from '../models/user';
import authRouter from '../route/auth';
import documentRouter from '../route/document';
import fourOhFour from '../middleware/four-oh-four';
import errorHandler from '../middleware/error-middleware';

const app = express();
app.enable('trust proxy'); // to retrieve info from the client on requests so we can log for auth actions

app.use(morgan('dev'));
app.use(cors({
  origin: process.env.CORS_ORIGINS,
  credentials: true,
}));

app.use(authRouter);
app.use(documentRouter);

app.use(fourOhFour);
app.use(errorHandler);

const state = {
  isOn: false,
  http: null,
};

export const start = () =>
  new Promise((resolve, reject) => {
    if(state.isOn)
      return reject(new Error('__SERVER_ERROR__: server is already running'));
    state.isOn = true;
    mongo.start()
      .then(() => {
        process.env.SECRET = randomBytes(256).toString('base64'); // dynamically generate SECRET for session tokens every time the server starts
        User.updateMany({}, {tokenSeed: undefined, tokenExpire: 0}, {runValidators: true}) // crypto updates the secret every time the server starts, we need to wipe out the current session tokens because they wont match the new secret
          .then(() => {
            state.http = Server(app); // express can't directly handle socket-io, so we send the app through http module
            state.http.listen(process.env.PORT, () => {
              console.log('__SERVER_UP__', process.env.API_URL);
              resolve();
            });
          });
      })
      .catch(reject);
  });

export const stop = () => 
  new Promise((resolve, reject) => {
    if(!state.isOn)
      return reject(new Error('__SERVER_ERROR__: server is already off'));
    return mongo.stop()
      .then(() => {
        state.http.close(() => {
          console.log('__SERVER_OFF__');
          state.isOn = false;
          state.http = null;
          resolve();
        });
      })
      .catch(reject);
  });