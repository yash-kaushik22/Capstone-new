export function formatBytes(n) {
  if (!Number.isFinite(n)) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

export const formatDate = (d) => (d ? new Date(d).toLocaleString() : '');

/** Split "a:b, c:d  e:f" into attribute strings. */
export const splitAttributes = (text) => text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);

export function passwordProblems(pw) {
  const issues = [];
  if (pw.length < 12) issues.push('at least 12 characters');
  if (!/[a-z]/i.test(pw) || !/[0-9\W_]/.test(pw)) issues.push('letters plus digits or symbols');
  return issues;
}
