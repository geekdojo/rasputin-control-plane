// A small reader for the FreeMarker our templates use: enough to find the
// data-model roots and fields a template reads, and the literal text a person
// sees. Not a FreeMarker parser; the templates test (TC-988-01) holds the
// real templates to it.

/** The template with every <#-- --> comment blanked, newlines kept. */
export function stripComments(src: string): string {
  return src.replace(/<#--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));
}

export interface Expr {
  text: string;
  /** 1-based line of the expression's start. */
  line: number;
}

function lineAt(src: string, i: number): number {
  return src.slice(0, i).split('\n').length;
}

/** The end of a ${ } interpolation starting at i (pointing past "${"). */
function interpolationEnd(src: string, i: number): number {
  let depth = 1;
  let quote = '';
  for (; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
  }
  return src.length;
}

export interface Tag {
  name: string; // "if", "list", "assign", "@layout.registrationLayout", ...
  body: string;
  line: number;
}

/** Every interpolation and every directive or macro-call tag. */
export function scan(src: string): { interpolations: Expr[]; tags: Tag[] } {
  const s = stripComments(src);
  const interpolations: Expr[] = [];
  for (let i = s.indexOf('${'); i >= 0; i = s.indexOf('${', i + 2)) {
    const end = interpolationEnd(s, i + 2);
    interpolations.push({ text: s.slice(i + 2, end), line: lineAt(s, i) });
  }
  const tags: Tag[] = [];
  for (const m of s.matchAll(/<([#@])([\w.]+)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g)) {
    tags.push({ name: (m[1] === '@' ? '@' : '') + m[2], body: m[3], line: lineAt(s, m.index ?? 0) });
  }
  return { interpolations, tags };
}

const KEYWORDS = new Set(['as', 'in', 'gt', 'gte', 'lt', 'lte', 'true', 'false', 'using']);

/** The names a template binds itself, which are therefore not data-model roots. */
export function locals(src: string): Set<string> {
  const out = new Set<string>();
  const { tags } = scan(src);
  for (const t of tags) {
    const add = (list: string) => list.split(',').forEach((n) => n.trim() && out.add(n.trim()));
    if (t.name === 'assign') {
      const m = /^\s*(\w+)/.exec(t.body);
      if (m) out.add(m[1]);
    } else if (t.name === 'list' || t.name === 'items') {
      const m = /\bas\s+([\w\s,]+?)\s*$/.exec(t.body);
      if (m) add(m[1]);
    } else if (t.name === 'import') {
      const m = /\bas\s+(\w+)/.exec(t.body);
      if (m) out.add(m[1]);
    } else if (t.name === 'macro') {
      for (const m of t.body.matchAll(/(\w+)(?=\s*=|\s|$)/g)) out.add(m[1]);
    } else if (t.name.startsWith('@')) {
      const m = /;\s*([\w\s,]+?)\s*\/?\s*$/.exec(t.body);
      if (m) add(m[1]);
    }
  }
  return out;
}

/** The expressions a tag evaluates (not the names it binds). */
function tagExpressions(t: Tag): string[] {
  switch (t.name) {
    case 'if':
    case 'elseif':
    case 'switch':
    case 'case':
      return [t.body];
    case 'list':
      return [t.body.replace(/\bas\s+[\w\s,]+$/, '')];
    case 'assign':
      return [t.body.replace(/^\s*\w+\s*=/, '')];
    default:
      if (t.name.startsWith('@')) {
        // name=value arguments: the values only; the loop variables after ';' are locals.
        const args = t.body.replace(/;[\s\S]*$/, '').replace(/\/\s*$/, '');
        return [args.replace(/(^|\s)\w+\s*=/g, ' ')];
      }
      return [];
  }
}

/** root -> its first-level fields read (root.field), over the template. */
export function reads(src: string): Map<string, Set<string>> {
  const { interpolations, tags } = scan(src);
  const exprs = [...interpolations.map((e) => e.text), ...tags.flatMap(tagExpressions)];
  const local = locals(src);
  const out = new Map<string, Set<string>>();
  for (const e of exprs) {
    // Strings out; a nested ${} inside one is an expression of its own.
    const nested = [...e.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]);
    const bare = e.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
    for (const piece of [bare, ...nested]) {
      for (const m of piece.matchAll(/(^|[^.?\w])([A-Za-z_]\w*)(\s*\.\s*([A-Za-z_]\w*))?/g)) {
        const root = m[2];
        if (KEYWORDS.has(root) || local.has(root)) continue;
        if (!out.has(root)) out.set(root, new Set());
        if (m[4]) out.get(root)!.add(m[4]);
      }
    }
  }
  return out;
}

/**
 * The literal text a person reads in a template: text outside tags and
 * interpolations, and the title, aria-label, placeholder and alt attribute
 * values with their interpolations removed. FreeMarker comments excluded.
 */
export function literalText(src: string): { where: string; text: string; line: number }[] {
  // Our templates carry only <script src> tags, which hold no text, and the
  // templates test refuses any other script.
  const s = stripComments(src).replace(/\$\{/g, '\u0000{');
  const out: { where: string; text: string; line: number }[] = [];
  const noInterp = (t: string) => {
    let r = '';
    for (let i = 0; i < t.length; i++) {
      if (t[i] === '\u0000') {
        i = interpolationEnd(t.replace(/\u0000/g, '$'), i + 2);
        r += ' ';
      } else r += t[i];
    }
    return r;
  };
  for (const m of s.matchAll(/\s(title|aria-label|placeholder|alt)="([^"]*)"/g)) {
    out.push({ where: m[1], text: noInterp(m[2]), line: lineAt(s, m.index ?? 0) });
  }
  const text = noInterp(s).replace(/<[^>]*>/g, (t) => t.replace(/[^\n]/g, ' '));
  text.split('\n').forEach((t, i) => {
    if (t.trim()) out.push({ where: 'text', text: t, line: i + 1 });
  });
  return out;
}
