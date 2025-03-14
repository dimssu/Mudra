import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt.util';
import { redisClient } from '../config/redis';

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = await verifyToken(token);

    // Optional: Check if token is in Redis
    const storedToken = await redisClient.get(`access_token:${decoded.userId}`);
    if (!storedToken || storedToken !== token) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = { id: decoded.userId };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}; 