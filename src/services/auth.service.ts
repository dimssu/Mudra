import { User, IUser } from '../models/User';
import { RefreshToken } from '../models/RefreshToken';
import { generateTokens, verifyToken } from '../utils/jwt.util';
import { redisClient } from '../config/redis';

export class AuthService {
  async register(email: string, password: string) {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new Error('Email already registered');
    }

    const user = new User({ email, password });
    await user.save();

    return { userId: user._id, email: user.email };
  }

  async login(email: string, password: string) {
    const user = await User.findOne({ email }) as IUser | null;
    if (!user) {
      throw new Error('Invalid credentials');
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      throw new Error('Invalid credentials');
    }

    const { accessToken, refreshToken } = await generateTokens(user._id.toString());

    // Store refresh token
    await RefreshToken.create({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    return { accessToken, refreshToken, user: { id: user._id, email: user.email } };
  }

  async refreshToken(token: string) {
    const decoded = await verifyToken(token);
    const storedToken = await RefreshToken.findOne({ 
      userId: decoded.userId,
      isRevoked: false 
    });

    if (!storedToken) {
      throw new Error('Invalid refresh token');
    }

    // Generate new tokens
    const { accessToken, refreshToken } = await generateTokens(decoded.userId);

    // Revoke old refresh token and save new one
    await RefreshToken.findByIdAndUpdate(storedToken._id, { isRevoked: true });
    await RefreshToken.create({
      userId: decoded.userId,
      token: refreshToken,
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