import { Router } from 'express';
import { UserController } from '../controllers/user.controller';
import { authenticate } from '../middlewares/auth.middleware';
import { requireRole } from '../middlewares/role.middleware';

const router = Router();

// All routes require authentication
router.use(authenticate);

// Get all users - only admins can access
router.get('/', requireRole(['SUPER_ADMIN', 'ORG_ADMIN']), UserController.getAllUsers);

// Get user by ID
router.get('/:id', UserController.getUserById);

// Update user
router.put('/:id', UserController.updateUser);

// Soft delete user - only admins can delete
router.delete('/:id', requireRole(['SUPER_ADMIN', 'ORG_ADMIN']), UserController.deleteUser);

// Permanently delete user - only super admins can do this
router.delete('/:id/permanent', requireRole(['SUPER_ADMIN']), UserController.permanentlyDeleteUser);

export default router; 