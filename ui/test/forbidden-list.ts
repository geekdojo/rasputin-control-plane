// ui/forbidden-words.json, read once for the test scans. __dirname is
// .test-out/test at run time (tsconfig.test.json), so the list is two up.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { ForbiddenList } from '../lib/forbidden-words';

export const UI_ROOT = path.join(__dirname, '..', '..');

export const forbiddenList = JSON.parse(readFileSync(path.join(UI_ROOT, 'forbidden-words.json'), 'utf8')) as ForbiddenList;
