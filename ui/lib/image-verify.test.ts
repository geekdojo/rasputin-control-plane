// The Add-node wizard's manual-verify panel, executed (geekdojo/geekdojo-brain#527).

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { imageVerifyState } from './image-verify';
import type { FlashableImage } from './types';

const base: FlashableImage = {
  version: '2026.09.4-dev.130',
  architecture: 'amd64',
  url: 'https://github.com/geekdojo/rasputin-openwrt-firewall/releases/download/2026.09.4-dev.130/fw-ab.img.gz',
  sha256: '455e19da50a95802d2684bae259edce8668a07c6a80aa4a7e3efb87a1d45dafd',
  image: 'fw-ab.img.gz',
};

describe('imageVerifyState', () => {
  test('a verified release with its manifest gets the commands, carrying the exact bytes', () => {
    const st = imageVerifyState({ ...base, signer: 'leaf-003', manifestB64: 'eyJ2In0=', manifestSigB64: 'MIIB' });
    assert.equal(st.kind, 'signed');
    if (st.kind !== 'signed') return;
    assert.match(st.commands, /printf '%s' 'eyJ2In0=' \| base64 -d > manifest\.json/);
    assert.match(st.commands, /printf '%s' 'MIIB' \| base64 -d > manifest\.json\.sig/);
    assert.match(st.commands, /openssl cms -verify -purpose any/);
  });

  test('a signer with no manifest is NOT presented as checkable (the #527 firewall descriptor)', () => {
    const st = imageVerifyState({ ...base, signer: 'Rasputin Bundle Signing leaf-003' });
    assert.equal(st.kind, 'unchecked');
  });

  test('half a pair is not checkable', () => {
    assert.equal(imageVerifyState({ ...base, signer: 'x', manifestB64: 'eyJ2In0=' }).kind, 'unchecked');
    assert.equal(imageVerifyState({ ...base, signer: 'x', manifestSigB64: 'MIIB' }).kind, 'unchecked');
  });

  test('a value that is not base64 never reaches a shell command', () => {
    const st = imageVerifyState({ ...base, signer: 'x', manifestB64: "a'; rm -rf ~; '", manifestSigB64: 'MIIB' });
    assert.equal(st.kind, 'unchecked');
  });

  test('nothing at all is an unsigned release', () => {
    assert.equal(imageVerifyState(base).kind, 'unsigned');
  });
});
