import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { User, IUser } from '../models/User';
import { RefreshToken } from '../models/RefreshToken';
import { generateTokens, verifyToken } from '../utils/jwt.util';
import { redisClient } from '../config/redis';
import { AuthenticationError, ValidationError } from '../utils/errors';
import { RedisCache } from '../utils/redis-cache';
import { verifyIdToken, getUserDetails } from '../utils/firebase.utils';
import * as admin from 'firebase-admin';

import { storeTokenAndCacheUser } from '../utils/auth.helper';

export default class AuthService {

  static async getAccessWithGoogle(idToken: string){
    const decodedToken = await verifyIdToken(idToken)
    const uid = decodedToken.uid

    const userDetails = await getUserDetails(uid)

    if(userDetails){
      let user: IUser | null = await User.findOne({ email: userDetails.email });

      if(!user){
        user = new User({ email: userDetails.email, authMethod: "google" });
        await user.save();
      }

      const { accessToken, refreshToken } = await generateTokens(user._id.toString());
      const tokenFamily = crypto.randomUUID();
      
      await RefreshToken.create({
        userId: user._id,
        token: refreshToken,
        family: tokenFamily,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      await RedisCache.set(`user:${user._id}`, {
        id: user._id,
        email: user.email,
        role: user.role,
      });

      return { accessToken, refreshToken, user: { id: user._id, email: user.email } };
    }

  }

  static async register(email: string, password: string, userData: Partial<IUser> = {}) {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ValidationError('Email already registered');
    }

    // Check if userName is provided and if it's already taken
    if (userData.userName) {
      const existingUserName = await User.findOne({ userName: userData.userName });
      if (existingUserName) {
        throw new ValidationError('Username already taken');
      }
    }

    // Create user with additional fields
    const user = new User({ 
      email, 
      password, 
      authMethod: "email/password",
      ...userData
    });
    
    await user.save();

    const { accessToken, refreshToken } = await generateTokens(user._id.toString());
    await storeTokenAndCacheUser(user, { accessToken, refreshToken });

    return { 
      accessToken, 
      refreshToken, 
      user: { 
        id: user._id, 
        email: user.email,
        userName: user.userName,
        first_name: user.first_name,
        last_name: user.last_name
      } 
    };
  }

  static async login(email: string, password: string) {
    const user = await User.findOne({ email });
    if (!user) {
      throw new AuthenticationError('Invalid credentials');
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      throw new AuthenticationError('Invalid credentials');
    }

    const { accessToken, refreshToken } = await generateTokens(user._id.toString());
    await storeTokenAndCacheUser(user, { accessToken, refreshToken });

    return { accessToken, refreshToken, user: { id: user._id, email: user.email } };
  }

  static async refreshToken(token: string) {
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

  static async logout(userId: string) {
    await RefreshToken.updateMany(
      { userId, isRevoked: false },
      { isRevoked: true }
    );
    await redisClient.del(`access_token:${userId}`);
  }

  static async verifyToken(accessToken: string) {
    try {
      const JWT_SECRET = process.env.JWT_SECRET as string
      const decodedToken = jwt.verify(accessToken, JWT_SECRET)
      return decodedToken
    } catch (error) {
      throw new AuthenticationError('Invalid token')
    }
  }
} 