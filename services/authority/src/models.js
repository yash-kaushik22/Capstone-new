import mongoose from 'mongoose';

const { Schema } = mongoose;

// Wrap any $-operator objects that reach a query filter in $eq (operator injection defence).
// Our own operators are marked with mongoose.trusted().
mongoose.set('strictQuery', true);
mongoose.set('sanitizeFilter', true);

/** Singleton holding the FAME public key and the master key sealed under AUTHORITY_KEK. */
const stateSchema = new Schema(
  {
    _id: { type: String, default: 'fame' },
    publicKey: { type: Schema.Types.Mixed, required: true },
    mskSealed: { type: String, required: true },
  },
  { timestamps: true, versionKey: false },
);

/** Attributes assigned by an administrator. `version` increases on every change. */
const attributesSchema = new Schema(
  {
    userId: { type: String, required: true, unique: true, match: /^[a-f0-9]{24}$/ },
    username: { type: String, required: true, match: /^[a-z0-9_]{3,32}$/ },
    attributes: { type: [String], default: [] },
    version: { type: Number, default: 1 },
    updatedBy: { type: String },
  },
  { timestamps: true, versionKey: false },
);

/** Last key issued per user, already sealed to that user's device key. */
const issuedKeySchema = new Schema(
  {
    userId: { type: String, required: true, unique: true },
    version: { type: Number, required: true },
    username: { type: String, required: true },
    ekThumbprint: { type: String, required: true },
    attributes: { type: [String], required: true },
    sealedKey: { type: String, required: true },
  },
  { timestamps: { createdAt: 'issuedAt', updatedAt: false }, versionKey: false },
);

const auditSchema = new Schema(
  {
    at: { type: Date, default: Date.now, index: true },
    actor: String,
    action: { type: String, required: true },
    target: String,
    details: Schema.Types.Mixed,
  },
  { versionKey: false },
);

export function createModels(conn) {
  return {
    State: conn.model('AuthorityState', stateSchema),
    Attributes: conn.model('UserAttributes', attributesSchema),
    IssuedKey: conn.model('IssuedKey', issuedKeySchema),
    Audit: conn.model('AuthorityAudit', auditSchema),
  };
}
