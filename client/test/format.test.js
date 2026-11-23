import { describe, it, expect } from 'vitest';
import { formatBytes, splitAttributes, passwordProblems } from '../src/format.js';
import { safeFilename } from '../src/services/files.js';
import { checkPolicy } from '../src/components/PolicyEditor.jsx';

describe('client helpers', () => {
  it('formats sizes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
  });

  it('splits attribute lists', () => {
    expect(splitAttributes(' dept:cse,role:faculty  year:4 ,')).toEqual(['dept:cse', 'role:faculty', 'year:4']);
  });

  it('sanitises download names', () => {
    expect(safeFilename('../../etc/passwd')).toBe('__.._etc_passwd');
    expect(safeFilename('a<b>:c?.txt')).toBe('a_b__c_.txt');
    expect(safeFilename('')).toBe('download');
    expect(safeFilename('.bashrc')).toBe('_bashrc');
  });

  it('checks password strength', () => {
    expect(passwordProblems('short')).toHaveLength(2);
    expect(passwordProblems('a long passphrase 42')).toEqual([]);
  });

  it('validates policies like the server does', () => {
    expect(checkPolicy('Dept:CSE and role:faculty')).toEqual({ canonical: 'dept:cse AND role:faculty', attributes: ['dept:cse', 'role:faculty'] });
    expect(checkPolicy('dept:cse AND').error).toBeTruthy();
  });
});
