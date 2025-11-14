const AuditLog = require('../models/audit-log');
const winston = require('winston');

class AuditService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({ filename: 'audit.log' })
      ]
    });
  }

  async logActivity(data) {
    const log = new AuditLog({
      userId: data.userId,
      action: data.action,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      details: data.details,
      status: data.status
    });

    await log.save();
    this.logger.info('Activity logged', { logId: log._id, ...data });
    return log;
  }

  async getUserActivity(userId, filters = {}) {
    const query = { userId, ...filters };
    return AuditLog.find(query).sort({ timestamp: -1 });
  }

  async getActivityByDateRange(startDate, endDate) {
    return AuditLog.find({
      timestamp: {
        $gte: startDate,
        $lte: endDate
      }
    }).sort({ timestamp: -1 });
  }

  async getFailedLoginAttempts(userId, timeWindow) {
    const since = new Date(Date.now() - timeWindow);
    return AuditLog.countDocuments({
      userId,
      action: 'login',
      status: 'failure',
      timestamp: { $gte: since }
    });
  }
}

module.exports = AuditService;