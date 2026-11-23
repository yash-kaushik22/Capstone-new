export class DecryptionError extends Error {
  constructor(message = 'Decryption failed: wrong key or tampered data') {
    super(message);
    this.name = 'DecryptionError';
  }
}

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
  }
}

/** Thrown when a user's attributes do not satisfy a ciphertext policy. */
export class PolicyNotSatisfiedError extends DecryptionError {
  constructor() {
    super('Your attributes do not satisfy this file\'s access policy');
    this.name = 'PolicyNotSatisfiedError';
  }
}

export class SignatureError extends Error {
  constructor(message = 'Signature verification failed') {
    super(message);
    this.name = 'SignatureError';
  }
}
