import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { sendSuccess } from '../utils/apiResponse.js';
import { authenticate } from '../middleware/auth.js';
import { createLogger } from '../utils/logger.js';
import {
  exportUserData,
  eraseUserData,
  getProcessingRecords,
} from '../services/gdpr/data-subject.service.js';

const logger = createLogger('gdpr-routes');
const router = Router();

// All GDPR routes require authentication
router.use(authenticate);

// Data export (Article 15 / Article 20 — right of access / data portability)
router.get('/export', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const data = await exportUserData(req.user!.id);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="codehardener-data-export.json"');
    sendSuccess(res, data);
  } catch (error) {
    next(error);
  }
});

// Data erasure (Article 17 — right to erasure / right to be forgotten)
router.delete('/erase', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Double-check the user confirms erasure
    const confirm = req.headers['x-confirm-erasure'];
    if (confirm !== 'DELETE-ALL-MY-DATA') {
      res.status(400).json({
        success: false,
        error: 'Data erasure requires X-Confirm-Erasure: DELETE-ALL-MY-DATA header',
      });
      return;
    }

    const result = await eraseUserData(req.user!.id);
    logger.info({ userId: req.user!.id }, 'GDPR erasure executed');
    sendSuccess(res, result);
  } catch (error) {
    next(error);
  }
});

// Processing records (Article 30)
router.get('/processing-records', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const records = await getProcessingRecords(req.user!.id);
    sendSuccess(res, { records });
  } catch (error) {
    next(error);
  }
});

export { router as gdprRoutes };
