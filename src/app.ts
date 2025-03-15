import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import { logger } from './utils/logger';
import authRoutes from './routes/auth.routes';
import { rateLimiter } from './middlewares/rateLimit.middleware';
import { errorHandler } from './middlewares/error.middleware';
import { validateRegister, validateLogin, validateRefreshToken } from './middlewares/validation.middleware';
import { AuthController } from './controllers/auth.controller';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
  credentials: true,
}));
app.use(compression());

// Logging middleware
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim()),
  },
}));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting for auth routes
app.use('/auth', rateLimiter);

// Routes
app.use('/auth', authRoutes);

// Auth routes with validation
app.post('/auth/register', validateRegister, AuthController.register);
app.post('/auth/login', validateLogin, AuthController.login);
app.post('/auth/refresh-token', validateRefreshToken, AuthController.refreshToken);

// Error handling middleware (should be last)
app.use(errorHandler);

export default app; 