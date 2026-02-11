const PasswordService = require('../src/utils/password');

describe('PasswordService', () => {
  describe('hash', () => {
    it('should hash a password', async () => {
      const password = 'TestPassword123!';
      const hash = await PasswordService.hash(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(0);
    });

    it('should generate different hashes for same password', async () => {
      const password = 'TestPassword123!';
      const hash1 = await PasswordService.hash(password);
      const hash2 = await PasswordService.hash(password);

      expect(hash1).not.toBe(hash2); // Different salts
    });
  });

  describe('compare', () => {
    it('should return true for correct password', async () => {
      const password = 'TestPassword123!';
      const hash = await PasswordService.hash(password);

      const isValid = await PasswordService.compare(password, hash);
      expect(isValid).toBe(true);
    });

    it('should return false for incorrect password', async () => {
      const password = 'TestPassword123!';
      const hash = await PasswordService.hash(password);

      const isValid = await PasswordService.compare('WrongPassword', hash);
      expect(isValid).toBe(false);
    });
  });

  describe('validate', () => {
    it('should validate a strong password', () => {
      const result = PasswordService.validate('StrongPass123!');

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject password too short', () => {
      const result = PasswordService.validate('Short1!');

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters long');
    });

    it('should reject password without uppercase', () => {
      const result = PasswordService.validate('lowercase123!');

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one uppercase letter');
    });

    it('should reject password without lowercase', () => {
      const result = PasswordService.validate('UPPERCASE123!');

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one lowercase letter');
    });

    it('should reject password without number', () => {
      const result = PasswordService.validate('NoNumbers!');

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one number');
    });

    it('should reject password without special character', () => {
      const result = PasswordService.validate('NoSpecial123');

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one special character');
    });
  });

  describe('generate', () => {
    it('should generate password of correct length', () => {
      const password = PasswordService.generate(16);

      expect(password.length).toBe(16);
    });

    it('should generate password with all required character types', () => {
      const password = PasswordService.generate(16);

      expect(/[A-Z]/.test(password)).toBe(true); // Uppercase
      expect(/[a-z]/.test(password)).toBe(true); // Lowercase
      expect(/[0-9]/.test(password)).toBe(true); // Number
      expect(/[!@#$%^&*(),.?":{}|<>]/.test(password)).toBe(true); // Special
    });

    it('should generate different passwords each time', () => {
      const password1 = PasswordService.generate();
      const password2 = PasswordService.generate();

      expect(password1).not.toBe(password2);
    });
  });
});
