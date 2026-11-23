import mongoose from 'mongoose';

const { Schema } = mongoose;

// Wrap any $-operator objects that reach a query filter in $eq (operator injection defence).
// Our own operators are marked with mongoose.trusted().
mongoose.set('strictQuery', true);
mongoose.set('sanitizeFilter', true);

const jwkSchema = new Schema(
  {
    kty: { type: String, enum: ['EC'], required: true },
    crv: { type: String, enum: ['P-256'], required: true },
    x: { type: String, required: true, match: /^[A-Za-z0-9_-]{43}$/ },
    y: { type: String, required: true, match: /^[A-Za-z0-9_-]{43}$/ },
  },
  { _id: false },
);

const userSchema = new Schema(
  {
    username: { type: String, required: true, unique: true, match: /^[a-z0-9_]{3,32}$/ },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    // Client-side KDF parameters (public). authHash = Argon2id(authKey); the password never reaches us.
    kdf: {
      alg: { type: String, required: true },
      iterations: { type: Number, required: true },
      salt: { type: String, required: true },
    },
    authHash: { type: String, required: true },
    encPublicKey: { type: jwkSchema, required: true },
    sigPublicKey: { type: jwkSchema, required: true },
    // Identity private keys encrypted with a key derived from the password on the client.
    vault: { type: String, required: true, maxlength: 4096 },
    failedLogins: { type: Number, default: 0 },
    lockedUntil: { type: Date, default: null },
  },
  { timestamps: true, versionKey: false },
);

const fileSchema = new Schema(
  {
    _id: { type: String, match: /^[A-Za-z0-9_-]{22}$/ }, // chosen by the client, bound into every AAD
    ownerId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    status: { type: String, enum: ['pending', 'ready'], default: 'pending', index: true },
    policy: { type: String, required: true, maxlength: 2048 },
    encMeta: { type: String, required: true, maxlength: 4096 },
    abeEnvelope: { type: Schema.Types.Mixed, required: true },
    ownerEnvelope: { type: String, required: true, maxlength: 1024 },
    manifest: { type: Schema.Types.Mixed, required: true },
    signature: { type: String, required: true, maxlength: 200 },
    blobName: { type: String, match: /^[a-f0-9]{48}$/ },
    size: { type: Number },
  },
  { timestamps: true, versionKey: false, minimize: false },
);
fileSchema.index({ status: 1, createdAt: -1 });

const auditSchema = new Schema(
  {
    at: { type: Date, default: Date.now, index: true },
    userId: String,
    username: String,
    action: { type: String, required: true },
    target: String,
    outcome: { type: String, enum: ['ok', 'denied', 'error'], default: 'ok' },
    ip: String,
    details: Schema.Types.Mixed,
  },
  { versionKey: false },
);

const revokedSchema = new Schema({
  _id: String, // jti
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
});

export function createModels(conn) {
  return {
    User: conn.model('User', userSchema),
    File: conn.model('File', fileSchema),
    Audit: conn.model('Audit', auditSchema),
    RevokedToken: conn.model('RevokedToken', revokedSchema),
  };
}
