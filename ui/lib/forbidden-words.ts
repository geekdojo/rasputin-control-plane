// The one matcher for ui/forbidden-words.json (geekdojo/geekdojo-brain#988,
// ui.md §4.4). Every TypeScript scan uses it: the sign-in theme's tests, the
// console source scan and the DOM test hook. The CI walk is Go and has its own
// copy of the rule over the same file, because it is another language.
//
// A word hits case-insensitively from a word start: not preceded by a letter,
// a digit or `_`, so "realms" and "tailscaled" hit and "RASPUTIN_HEADSCALE"
// does not. A multi-word entry matches across any run of white space, a line
// break included. An exemption removes its one exact string, in its one file,
// before matching.

export interface ForbiddenList {
  words: string[];
  exemptions: { file: string; text: string; reason: string }[];
}

export interface Hit {
  /** The list entry that matched. */
  word: string;
  /** The text as written where it matched. */
  match: string;
  /** Its offset in the text. */
  index: number;
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The pattern for one list entry. */
export function wordPattern(word: string): RegExp {
  const body = word.trim().split(/\s+/).map(escape).join('\\s+');
  return new RegExp(`(?<![\\p{L}\\p{N}_])${body}`, 'giu');
}

/**
 * The hits in text. `file`, when given, is the path (relative to ui/) whose
 * exemptions apply.
 */
export function findForbidden(list: ForbiddenList, text: string, file?: string): Hit[] {
  let t = text;
  if (file !== undefined) {
    for (const ex of list.exemptions) {
      if (ex.file === file && ex.text !== '') {
        t = t.split(ex.text).join(' '.repeat(ex.text.length));
      }
    }
  }
  const hits: Hit[] = [];
  for (const word of list.words) {
    for (const m of t.matchAll(wordPattern(word))) {
      hits.push({ word, match: m[0], index: m.index ?? 0 });
    }
  }
  return hits.sort((a, b) => a.index - b.index);
}

/** One sentence naming each hit, for a failing assertion. */
export function describeHits(hits: Hit[], where: string): string {
  return hits.map((h) => `${where} reads "${h.match}" (forbidden: ${h.word})`).join('; ');
}
