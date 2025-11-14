// packages/auth/src/models/role.js
const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema({
  resource: { type: String, required: true },
  actions: [{
    type: String,
    enum: ['create', 'read', 'update', 'delete', 'manage'],
    required: true
  }]
}, { _id: false });

const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, trim: true },
  permissions: { type: [permissionSchema], default: [] },
  description: { type: String, default: '' },
  isSystem: { type: Boolean, default: false }
}, { timestamps: true });

// Ensure case-insensitive uniqueness for name at application level
roleSchema.index({ name: 1 }, { unique: true });

/**
 * Utility: check if role allows an action on a resource
 * resource can be string or wildcard
 */
roleSchema.methods.can = function(resource, action) {
  if (!this.permissions || !Array.isArray(this.permissions)) return false;
  return this.permissions.some(p => {
    const resourceMatches = (p.resource === resource) || (p.resource === '*');
    return resourceMatches && p.actions && p.actions.includes(action);
  });
};

module.exports = mongoose.model('Role', roleSchema);
