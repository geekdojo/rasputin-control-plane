// Builds the Rasputin login theme into a directory theme Keycloak loads from
// themes/rasputin (geekdojo/geekdojo-brain#988, ui.md §4.1). Node built-ins
// only: no Maven, no Keycloakify, no new dependency.
//
//   node ui/identity-theme/build.mjs <OUT>      (npm run identity-theme:build -- <OUT>)
//
// <OUT> must not exist, or be an empty directory. It receives:
//   login/                      src/login, as written
//   login/resources/css/        plus ui/styles/tokens.css and the fonts it names
//   resource-allowlist.json     the files the door proxy (Identity 4.3,
//                               geekdojo/geekdojo-brain#985) may serve:
//     keycloak  the pinned release the theme was reviewed at (coverage.json)
//     login     paths under /resources/<v>/login/rasputin/: every file we
//               ship under login/resources/, and each parent-base resource a
//               template or module references
//     common    paths under /resources/<v>/common/keycloak/ that a module imports
//
// It refuses, with exit status 1 and one sentence naming the file:
//   - a missing source, token file or font;
//   - a reference (a template's ${url.resourcesPath}/..., a style sheet's url(),
//     a module's import) that resolves neither to our files nor to a base file
//     the snapshot lists (upstream/<v>/resources-sha256.json);
//   - a bare import specifier in a module we ship, or in a parent-base module
//     we reference (judged by upstream/<v>/module-imports.json, which the base
//     snapshot test holds current): a browser resolves a bare name only through
//     an import map, and the sign-in pages carry no inline script to hold one;
//   - a failed write.
// A wrong argument count exits 2 with a usage sentence.
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const UI = path.dirname(HERE);
const SRC = path.join(HERE, 'src', 'login');
const TOKENS = path.join(UI, 'styles', 'tokens.css');
const FONTS = path.join(UI, 'styles', 'fonts');

class Refusal extends Error {}

function refuse(sentence) {
  throw new Refusal(sentence);
}

function readText(file, what) {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return refuse(`The ${what} ${file} is missing, so the theme cannot be built.`);
  }
}

/** Every file under dir, as paths relative to it with forward slashes. */
function walk(dir, rel = '') {
  const out = [];
  for (const ent of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const r = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...walk(dir, r));
    else out.push(r);
  }
  return out;
}

/** The import specifiers of an ES module's source. */
export function importSpecifiers(source) {
  const out = [];
  const re = /(?:^|[\s;])import\s*(?:[^'"]*?\sfrom\s*)?['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/gm;
  for (const m of source.matchAll(re)) out.push(m[1] ?? m[2]);
  return out;
}

function isBare(spec) {
  return !(spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('/'));
}

/**
 * Where a relative specifier in the module at login-resources path `from`
 * (e.g. "js/webauthnRegister.js") lands: { area: 'login' | 'common', path }.
 * The theme's resources are served at /resources/<v>/login/rasputin/, common
 * at /resources/<v>/common/keycloak/.
 */
function resolveSpecifier(from, spec) {
  const url = new URL(spec, `https://door.invalid/resources/v/login/rasputin/${from}`);
  const p = url.pathname;
  const login = '/resources/v/login/rasputin/';
  const common = '/resources/v/common/keycloak/';
  if (p.startsWith(login)) return { area: 'login', path: p.slice(login.length) };
  if (p.startsWith(common)) return { area: 'common', path: p.slice(common.length) };
  return { area: 'elsewhere', path: p };
}

function build(out) {
  const coverage = JSON.parse(readText(path.join(HERE, 'coverage.json'), 'coverage record'));
  const version = coverage.keycloak;
  const upstream = path.join(HERE, 'upstream', version);
  const baseFiles = JSON.parse(readText(path.join(upstream, 'resources-sha256.json'), 'base snapshot list')).files.map((f) => f.path);
  const baseImports = JSON.parse(readText(path.join(upstream, 'module-imports.json'), 'base module import list')).imports;
  readText(path.join(SRC, 'theme.properties'), 'theme source');

  // What we ship under login/resources/, the tokens and fonts included.
  const tokens = readText(TOKENS, 'token file');
  const fonts = [...tokens.matchAll(/url\(\s*['"]?\.\/fonts\/([^'")]+)['"]?\s*\)/g)].map((m) => m[1]);
  for (const f of fonts) {
    if (!existsSync(path.join(FONTS, f))) refuse(`The font ${path.join(FONTS, f)} that tokens.css names is missing, so the theme cannot be built.`);
  }
  const ours = new Set(walk(path.join(SRC, 'resources')));
  ours.add('css/tokens.css');
  for (const f of fonts) ours.add(`css/fonts/${f}`);
  ours.add('css/fonts/OFL.txt');

  const baseLogin = new Set(baseFiles.filter((k) => k.startsWith('login/resources/')).map((k) => k.slice('login/resources/'.length)));
  const baseCommon = new Set(baseFiles.filter((k) => k.startsWith('common/keycloak/')).map((k) => k.slice('common/keycloak/'.length)));
  const loginRefs = new Set();
  const commonRefs = new Set();

  // A login-resources path a file of ours references: ours, or base's.
  const needLogin = (p, who) => {
    if (ours.has(p)) return;
    if (baseLogin.has(p)) {
      loginRefs.add(p);
      return;
    }
    refuse(`${who} references ${p}, which is neither a theme file nor a base file at ${version}, so the page would load nothing there.`);
  };

  // Templates: ${url.resourcesPath}/... and ${url.resourcesCommonPath}/...
  for (const t of walk(SRC).filter((f) => f.endsWith('.ftl'))) {
    const src = readText(path.join(SRC, t), 'template');
    // A path built from a variable (template.ftl's ${style}) is checked
    // where its value is written: theme.properties, below.
    for (const m of src.matchAll(/\$\{url\.resourcesPath\}\/([^"'\s<>]+)/g)) {
      if (!m[1].includes('${')) needLogin(m[1], `The template ${t}`);
    }
    for (const m of src.matchAll(/\$\{url\.resourcesCommonPath\}\/([^"'\s<>]+)/g)) {
      if (!baseCommon.has(m[1])) refuse(`The template ${t} references common ${m[1]}, which is not a base file at ${version}.`);
      commonRefs.add(m[1]);
    }
  }
  // theme.properties' style sheets.
  const props = readText(path.join(SRC, 'theme.properties'), 'theme source');
  const styles = /^styles=(.*)$/m.exec(props);
  for (const s of (styles ? styles[1] : '').split(/\s+/).filter(Boolean)) needLogin(s, 'theme.properties');
  // Style sheets' url()s, relative to the sheet.
  for (const css of [...ours].filter((f) => f.endsWith('.css'))) {
    const text = css === 'css/tokens.css' ? tokens : readText(path.join(SRC, 'resources', css), 'style sheet');
    for (const m of text.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)) {
      if (m[1].startsWith('data:')) continue;
      const r = resolveSpecifier(css, m[1]);
      if (r.area !== 'login') refuse(`The style sheet ${css} references ${m[1]}, outside the theme.`);
      needLogin(r.path, `The style sheet ${css}`);
    }
  }
  // Modules: ours, then every parent-base module they reach.
  const queue = [...ours].filter((f) => f.endsWith('.js'));
  queue.push(...[...loginRefs].filter((f) => f.endsWith('.js')));
  const seen = new Set();
  while (queue.length) {
    const mod = queue.shift();
    if (seen.has(mod)) continue;
    seen.add(mod);
    let specs;
    if (ours.has(mod)) {
      specs = importSpecifiers(readText(path.join(SRC, 'resources', mod), 'module'));
    } else {
      specs = baseImports[path.basename(mod)];
      if (!specs) refuse(`The base module ${mod} has no entry in upstream/${version}/module-imports.json, so its imports cannot be checked.`);
    }
    const who = ours.has(mod) ? `The module ${mod}` : `The base module ${mod}, which the theme loads,`;
    for (const spec of specs) {
      if (isBare(spec)) refuse(`${who} imports the bare specifier "${spec}", which a browser resolves only through an import map, and the sign-in pages carry none.`);
      const r = resolveSpecifier(mod, spec);
      if (r.area === 'login') {
        needLogin(r.path, who);
        queue.push(r.path);
      } else if (r.area === 'common') {
        if (!baseCommon.has(r.path)) refuse(`${who} imports ${spec}, which is not a common file at ${version}.`);
        commonRefs.add(r.path);
      } else {
        refuse(`${who} imports ${spec}, outside the theme's resources.`);
      }
    }
  }

  // Write.
  if (existsSync(out) && (!statSync(out).isDirectory() || readdirSync(out).length > 0)) {
    refuse(`The output ${out} already exists and is not an empty directory, so the build will not write into it.`);
  }
  try {
    for (const f of walk(SRC)) {
      const dst = path.join(out, 'login', f);
      mkdirSync(path.dirname(dst), { recursive: true });
      copyFileSync(path.join(SRC, f), dst);
    }
    const css = path.join(out, 'login', 'resources', 'css');
    mkdirSync(path.join(css, 'fonts'), { recursive: true });
    copyFileSync(TOKENS, path.join(css, 'tokens.css'));
    for (const f of [...fonts, 'OFL.txt']) copyFileSync(path.join(FONTS, f), path.join(css, 'fonts', f));
    const allowlist = {
      keycloak: version,
      login: [...new Set([...ours, ...loginRefs])].sort(),
      common: [...commonRefs].sort(),
    };
    writeFileSync(path.join(out, 'resource-allowlist.json'), JSON.stringify(allowlist, null, 2) + '\n');
  } catch (e) {
    refuse(`The theme could not be written to ${out}: ${e.message}`);
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] === '') {
    process.stderr.write('Usage: node build.mjs <OUT>, where OUT is the directory to write the built theme into; it must not exist or be empty.\n');
    process.exit(2);
  }
  try {
    build(path.resolve(args[0]));
  } catch (e) {
    if (e instanceof Refusal) {
      process.stderr.write(e.message + '\n');
      process.exit(1);
    }
    throw e;
  }
}
