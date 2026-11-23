import { describe, it, expect } from 'vitest';
import {
  parsePolicy, formatPolicy, canonicalPolicy, satisfies, toLsss, satisfyingRows, leaves, LIMITS,
} from '../src/abe/policy.js';
import { PolicyError } from '../src/errors.js';

describe('policy parser', () => {
  it('parses precedence (AND binds tighter than OR) and normalises case', () => {
    expect(canonicalPolicy('Dept:CSE and ROLE:faculty or user:alice')).toBe('(dept:cse AND role:faculty) OR user:alice');
    expect(canonicalPolicy('dept:cse && (role:faculty || role:hod)')).toBe('dept:cse AND (role:faculty OR role:hod)');
    expect(canonicalPolicy('"dept:cse" AND "year:2026"')).toBe('dept:cse AND year:2026');
  });

  it('flattens nested operators of the same type', () => {
    expect(canonicalPolicy('(a:1 AND b:2) AND c:3')).toBe('a:1 AND b:2 AND c:3');
    expect(canonicalPolicy('a:1 OR (b:2 OR c:3)')).toBe('a:1 OR b:2 OR c:3');
  });

  it('is idempotent', () => {
    const p = canonicalPolicy('(x:1 or y:2) and (z:3 or (w:4 and v:5))');
    expect(canonicalPolicy(p)).toBe(p);
  });

  it.each([
    '', '   ', 'dept:cse AND', 'AND dept:cse', '(dept:cse', 'dept:cse)', 'dept', 'dept:', ':cse',
    'dept:cse role:x', 'dept:c$e', 'dept:cse OR OR x:y', 'a|b:c',
  ])('rejects %j', (src) => {
    expect(() => parsePolicy(src)).toThrow(PolicyError);
  });

  it('enforces size limits', () => {
    const many = Array.from({ length: LIMITS.maxLeaves + 1 }, (_, i) => `a:${i}`).join(' OR ');
    expect(() => parsePolicy(many)).toThrow(/more than/);
    const deep = `${'('.repeat(20)}a:1${')'.repeat(20)}`;
    expect(() => parsePolicy(deep)).toThrow(/deeply/);
  });

  it('evaluates satisfaction', () => {
    const ast = parsePolicy('(dept:cse AND role:faculty) OR user:alice');
    expect(satisfies(ast, ['dept:cse', 'role:faculty'])).toBe(true);
    expect(satisfies(ast, ['user:alice'])).toBe(true);
    expect(satisfies(ast, ['dept:cse'])).toBe(false);
    expect(satisfies(ast, [])).toBe(false);
  });
});

describe('LSSS (Lewko-Waters)', () => {
  const policies = [
    'a:1',
    'a:1 AND b:2',
    'a:1 OR b:2',
    '(a:1 AND b:2) OR c:3',
    'a:1 AND (b:2 OR c:3) AND d:4',
    '(a:1 OR b:2) AND (c:3 OR d:4) AND (e:5 OR (f:6 AND g:7))',
    'a:1 AND a:1 OR b:2', // repeated attribute
  ];

  it.each(policies)('chosen rows reconstruct (1,0,...,0) iff the policy is satisfied: %s', (src) => {
    const ast = parsePolicy(src);
    const { rows, cols } = toLsss(ast);
    const names = [...new Set(leaves(ast))];
    expect(rows.map((r) => r.attr)).toEqual(leaves(ast));
    // exhaustive over all attribute subsets
    for (let mask = 0; mask < 1 << names.length; mask++) {
      const set = new Set(names.filter((_, i) => mask & (1 << i)));
      const chosen = satisfyingRows(ast, set);
      expect(Boolean(chosen)).toBe(satisfies(ast, set));
      if (chosen) {
        const v = new Array(cols).fill(0);
        for (const i of chosen) {
          expect(set.has(rows[i].attr)).toBe(true);
          rows[i].vec.forEach((m, j) => (v[j] += m));
        }
        expect(v).toEqual([1, ...new Array(cols - 1).fill(0)]);
      }
    }
  });

  it('formats back to the same matrix', () => {
    const ast = parsePolicy('(a:1 or b:2) and c:3');
    expect(toLsss(parsePolicy(formatPolicy(ast)))).toEqual(toLsss(ast));
  });
});
