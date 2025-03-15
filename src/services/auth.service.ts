import crypto from 'crypto';
import { User, IUser } from '../models/User';
import { RefreshToken } from '../models/RefreshToken';
import { generateTokens, verifyToken } from '../utils/jwt.util';
import { redisClient } from '../config/redis';
import { AuthenticationError, ValidationError } from '../utils/errors';
import { RedisCache } from '../utils/redis-cache';

export class AuthService {
  async register(email: string, password: string) {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ValidationError('Email already registered');
    }

    const user = new User({ email, password });
    await user.save();

    return { userId: user._id, email: user.email };
  }

  async login(email: string, password: string) {
    const user = await User.findOne({ email });
    if (!user) {
      throw new AuthenticationError('Invalid credentials');
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      throw new AuthenticationError('Invalid credentials');
    }

    const { accessToken, refreshToken } = await generateTokens(user._id.toString());
    
    // Generate a unique family ID for refresh token tracking
    const tokenFamily = crypto.randomUUID();
    
    await RefreshToken.create({
      userId: user._id,
      token: refreshToken,
      family: tokenFamily,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // Cache user data in Redis
    await RedisCache.set(`user:${user._id}`, {
      id: user._id,
      email: user.email,
      role: user.role,
    });

    return { accessToken, refreshToken, user: { id: user._id, email: user.email } };
  }

  async refreshToken(token: string) {
    const storedToken = await RefreshToken.findOne({ 
      token: crypto.createHash('sha256').update(token).digest('hex'),
      isRevoked: false 
    });

    if (!storedToken) {
      throw new AuthenticationError('Invalid refresh token');
    }

    // Revoke all refresh tokens in the same family to prevent reuse
    await RefreshToken.updateMany(
      { family: storedToken.family },
      { isRevoked: true }
    );

    const { accessToken, refreshToken } = await generateTokens(storedToken.userId.toString());
    
    // Create new refresh token with new family
    await RefreshToken.create({
      userId: storedToken.userId,
      token: refreshToken,
      family: crypto.randomUUID(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return { accessToken, refreshToken };
  }

  async logout(userId: string) {
    await RefreshToken.updateMany(
      { userId, isRevoked: false },
      { isRevoked: true }
    );
    await redisClient.del(`access_token:${userId}`);
  }
} 