// The console source scan (geekdojo/geekdojo-brain#988, ui.md §4.4): the
// copy a person reads in app/, components/ and non-test lib/, found with the
// TypeScript compiler API, checked against ui/forbidden-words.json.
//
// What a person reads: JSX text; the title, aria-label, placeholder and alt
// attributes; and string and template literals, which become rendered text
// through props, state and helpers. Left out, because nobody reads them:
// comments (trivia the parser drops), identifiers, module specifiers, the
// operands of a comparison and case labels (values matched against, such as a
// backend mode the api reports), literal types, property names, and the JSX
// attributes that only address things (className, href, key and the like).
import ts from 'typescript';
import { findForbidden, type ForbiddenList, type Hit } from '../lib/forbidden-words';

export interface SourceHit extends Hit {
  file: string;
  line: number;
  /** "text", or the attribute or literal kind it was read from. */
  where: string;
}

const READ_ATTRIBUTES = new Set(['title', 'aria-label', 'placeholder', 'alt']);
const ADDRESS_ATTRIBUTES = new Set(['className', 'href', 'src', 'key', 'id', 'htmlFor', 'type', 'name', 'role', 'rel', 'target', 'style']);
const COMPARISONS = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
]);

function attributeName(a: ts.JsxAttribute): string {
  return a.name.getText();
}

/** Whether a literal is a value matched against or an address, not copy. */
function unread(node: ts.Node): boolean {
  for (let n: ts.Node = node, p = node.parent; p; n = p, p = p.parent) {
    if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isExternalModuleReference(p)) return true;
    if (ts.isCallExpression(p) && n !== p.expression) {
      const callee = p.expression.getText();
      if (callee === 'require' || p.expression.kind === ts.SyntaxKind.ImportKeyword) return true;
    }
    if (ts.isBinaryExpression(p) && COMPARISONS.has(p.operatorToken.kind)) return true;
    if (ts.isCaseClause(p) && n === p.expression) return true;
    if (ts.isLiteralTypeNode(p)) return true;
    if (ts.isPropertyAssignment(p) && n === p.name) return true;
    if (ts.isElementAccessExpression(p) && n === p.argumentExpression) return true;
    if (ts.isJsxAttribute(p)) {
      const name = attributeName(p);
      return ADDRESS_ATTRIBUTES.has(name) || name.startsWith('data-');
    }
    // A literal stops being "the value of" something once a statement or a
    // JSX element is reached.
    if (ts.isStatement(p) || ts.isJsxElement(p) || ts.isJsxSelfClosingElement(p)) return false;
  }
  return false;
}

function literalText(node: ts.Node): string | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) return node.text;
  return undefined;
}

/** The forbidden words a person would read in one source file. */
export function scanSource(list: ForbiddenList, file: string, source: string): SourceHit[] {
  const kind = file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, kind);
  const hits: SourceHit[] = [];
  const check = (text: string, node: ts.Node, where: string) => {
    for (const h of findForbidden(list, text, file)) {
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      hits.push({ ...h, file, line: line + 1, where });
    }
  };
  const visit = (node: ts.Node, readAttr?: string): void => {
    if (ts.isJsxText(node)) {
      check(node.text, node, 'text');
      return;
    }
    if (ts.isJsxAttribute(node)) {
      const name = attributeName(node);
      if (READ_ATTRIBUTES.has(name)) {
        if (node.initializer) visit(node.initializer, name);
        return;
      }
    }
    const text = literalText(node);
    if (text !== undefined) {
      if (readAttr) check(text, node, readAttr);
      else if (!unread(node)) check(text, node, 'string');
      return;
    }
    ts.forEachChild(node, (c) => visit(c, readAttr));
  };
  visit(sf);
  return hits;
}
