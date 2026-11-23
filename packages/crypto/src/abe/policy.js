/**
 * Access-policy language for CP-ABE.
 *
 *   policy   := orExpr
 *   orExpr   := andExpr ( ("OR" | "||") andExpr )*
 *   andExpr  := atom ( ("AND" | "&&") atom )*
 *   atom     := attribute | "(" orExpr ")"
 *   attribute:= key ":" value        e.g.  dept:cse   role:faculty   user:alice
 *
 * Attributes are case-insensitive and normalised to lowercase. AND binds tighter
 * than OR. The policy is turned into a monotone span program (LSSS matrix) with
 * the Lewko-Waters construction, which is what the FAME scheme consumes.
 */
import { PolicyError } from '../errors.js';

export const ATTRIBUTE_RE = /^[a-z0-9][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.@-]{0,63}$/;
export const LIMITS = Object.freeze({ maxLength: 2048, maxLeaves: 32, maxDepth: 16 });

export function normalizeAttribute(raw) {
  const a = String(raw).trim().toLowerCase();
  if (!ATTRIBUTE_RE.test(a)) throw new PolicyError(`Invalid attribute "${raw}" (expected key:value, e.g. dept:cse)`);
  return a;
}

function tokenize(src) {
  const tokens = [];
  const re = /\s*(?:(\()|(\))|(&&|\|\|)|"([^"]*)"|([A-Za-z0-9_.@:-]+))/y;
  let pos = 0;
  while (pos < src.length) {
    if (/^\s*$/.test(src.slice(pos))) break;
    re.lastIndex = pos;
    const m = re.exec(src);
    if (!m) throw new PolicyError(`Unexpected character at position ${pos + 1}`);
    pos = re.lastIndex;
    if (m[1]) tokens.push({ t: '(' });
    else if (m[2]) tokens.push({ t: ')' });
    else if (m[3]) tokens.push({ t: m[3] === '&&' ? 'AND' : 'OR' });
    else if (m[4] !== undefined) tokens.push({ t: 'ATTR', v: normalizeAttribute(m[4]) });
    else {
      const word = m[5];
      const upper = word.toUpperCase();
      if (upper === 'AND' || upper === 'OR') tokens.push({ t: upper });
      else tokens.push({ t: 'ATTR', v: normalizeAttribute(word) });
    }
  }
  return tokens;
}

/** Parse a policy string into an AST: {type:'attr',name} | {type:'and'|'or',children:[...]} */
export function parsePolicy(src) {
  if (typeof src !== 'string' || !src.trim()) throw new PolicyError('Policy is empty');
  if (src.length > LIMITS.maxLength) throw new PolicyError('Policy is too long');
  const tokens = tokenize(src);
  let i = 0;
  let leaves = 0;
  const peek = () => tokens[i]?.t;

  function parseOr(depth) {
    if (depth > LIMITS.maxDepth) throw new PolicyError('Policy is nested too deeply');
    const children = [parseAnd(depth)];
    while (peek() === 'OR') {
      i++;
      children.push(parseAnd(depth));
    }
    return children.length === 1 ? children[0] : flatten('or', children);
  }
  function parseAnd(depth) {
    const children = [parseAtom(depth)];
    while (peek() === 'AND') {
      i++;
      children.push(parseAtom(depth));
    }
    return children.length === 1 ? children[0] : flatten('and', children);
  }
  function parseAtom(depth) {
    const tok = tokens[i];
    if (!tok) throw new PolicyError('Policy ends unexpectedly');
    if (tok.t === '(') {
      i++;
      const node = parseOr(depth + 1);
      if (peek() !== ')') throw new PolicyError('Missing closing parenthesis');
      i++;
      return node;
    }
    if (tok.t === 'ATTR') {
      i++;
      if (++leaves > LIMITS.maxLeaves) throw new PolicyError(`Policy has more than ${LIMITS.maxLeaves} attributes`);
      return { type: 'attr', name: tok.v };
    }
    throw new PolicyError(`Unexpected "${tok.t}"`);
  }

  const ast = parseOr(0);
  if (i !== tokens.length) throw new PolicyError(`Unexpected "${tokens[i].t === 'ATTR' ? tokens[i].v : tokens[i].t}"`);
  return ast;
}

function flatten(type, children) {
  const out = [];
  for (const c of children) {
    if (c.type === type) out.push(...c.children);
    else out.push(c);
  }
  return { type, children: out };
}

/** Canonical text form. Two policies with the same canonical form produce the same LSSS matrix. */
export function formatPolicy(ast, parentType = null) {
  if (ast.type === 'attr') return ast.name;
  const s = ast.children.map((c) => formatPolicy(c, ast.type)).join(ast.type === 'and' ? ' AND ' : ' OR ');
  return parentType ? `(${s})` : s;
}

export const canonicalPolicy = (src) => formatPolicy(parsePolicy(src));

/** Leaves in left-to-right order. Row i of the LSSS matrix belongs to leaf i. */
export function leaves(ast, out = []) {
  if (ast.type === 'attr') out.push(ast.name);
  else ast.children.forEach((c) => leaves(c, out));
  return out;
}

export const attributesOf = (ast) => [...new Set(leaves(ast))];

/** Does a set of attributes satisfy the policy? */
export function satisfies(ast, attrSet) {
  const set = attrSet instanceof Set ? attrSet : new Set(attrSet);
  if (ast.type === 'attr') return set.has(ast.name);
  if (ast.type === 'and') return ast.children.every((c) => satisfies(c, set));
  return ast.children.some((c) => satisfies(c, set));
}

/**
 * Lewko-Waters: monotone boolean formula -> LSSS matrix with entries in {-1,0,1}.
 * Returns { rows: [{ attr, vec:number[] }], cols }. The target vector is (1,0,...,0).
 */
export function toLsss(ast) {
  const rows = [];
  let c = 1;
  const pad = (v, n) => [...v, ...new Array(n - v.length).fill(0)];
  function walk(node, v) {
    if (node.type === 'attr') {
      rows.push({ attr: node.name, vec: v });
      return;
    }
    if (node.type === 'or') {
      node.children.forEach((child) => walk(child, v));
      return;
    }
    // AND with k children == nested binary AND(x1, AND(x2, ...)).
    let current = v;
    for (let k = 0; k < node.children.length - 1; k++) {
      const left = [...pad(current, c), 1];
      const right = [...new Array(c).fill(0), -1];
      c++;
      walk(node.children[k], left);
      current = right;
    }
    walk(node.children[node.children.length - 1], current);
  }
  walk(ast, [1]);
  return { rows: rows.map((r) => ({ attr: r.attr, vec: pad(r.vec, c) })), cols: c };
}

/**
 * Pick a minimal set of leaf indices that satisfies the policy, or null.
 * For Lewko-Waters matrices the reconstruction coefficients of such a set are all 1:
 * the chosen rows sum to (1,0,...,0).
 */
export function satisfyingRows(ast, attrSet) {
  const set = attrSet instanceof Set ? attrSet : new Set(attrSet);
  let next = 0;
  function walk(node) {
    if (node.type === 'attr') {
      const idx = next++;
      return set.has(node.name) ? [idx] : null;
    }
    const results = node.children.map(walk); // walk every child so leaf numbering stays aligned
    if (node.type === 'and') return results.every(Boolean) ? results.flat() : null;
    const ok = results.filter(Boolean);
    if (!ok.length) return null;
    return ok.reduce((best, r) => (r.length < best.length ? r : best));
  }
  return walk(ast);
}
