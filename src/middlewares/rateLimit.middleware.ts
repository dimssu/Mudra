import { Request, Response, NextFunction } from 'express';
import { redisClient } from '../config/redis';
import { logger } from '@/utils/logger';

const RATE_LIMITS = {
  login: { window: 300, max: 5 },
  register: { window: 3600, max: 3 },
  refreshToken: { window: 300, max: 10 }
};

export const rateLimiter = (endpoint: keyof typeof RATE_LIMITS) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const ip = req.ip;
      const key = `rateLimit:${endpoint}:${ip}`;
      const { window, max } = RATE_LIMITS[endpoint];
      
      const requests = await redisClient.incr(key);
      
      if (requests === 1) {
        await redisClient.expire(key, window);
      }

      if (requests > max) {
        logger.warn(`Rate limit exceeded for IP: ${ip} on ${endpoint}`);
        return res.status(429).json({
          error: 'Too many requests, please try again later.',
          retryAfter: await redisClient.ttl(key),
        });
      }

      next();
    } catch (error) {
      logger.error('Rate limiter error:', error);
      next();
    }
  };
}; 