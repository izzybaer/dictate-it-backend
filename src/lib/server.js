import cors from 'cors';
import {Server} from 'http';
import morgan from 'morgan';
import express from 'express';
import {randomBytes} from 'crypto';

import * as mongo from './mongo.js';
import User from '../models/user.js';
import authRouter from '../route/auth.js';
