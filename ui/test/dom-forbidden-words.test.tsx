// TC-988-08: every DOM test asserts the forbidden-words scan, because
// render() and click() run it (geekdojo/geekdojo-brain#988).
import { click, render } from './dom';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { useState } from 'react';

test('TC-988-08: render() fails on a forbidden word in the text, naming it', async () => {
  await assert.rejects(render(<p>Headscale is down</p>), /forbidden word.*the text reads "Headscale"/);
});

test('TC-988-08: render() fails on a forbidden word in a title, naming the attribute', async () => {
  await assert.rejects(
    render(<button title="Restart Headscale">restart</button>),
    /the title attribute of <button> reads "Headscale"/,
  );
});

function Reveal() {
  const [shown, setShown] = useState(false);
  return (
    <button type="button" onClick={() => setShown(true)}>
      {shown ? 'Headscale' : 'show'}
    </button>
  );
}

test('TC-988-08: click() fails when the re-render shows a forbidden word', async () => {
  assert.equal(document.body.textContent?.includes('Headscale'), false, 'an earlier test left its page behind');
  const r = await render(<Reveal />);
  const b = r.container.querySelector('button');
  assert.ok(b);
  await assert.rejects(click(b), /the text reads "Headscale"/);
  await r.unmount();
});

test('TC-988-08: a page with none renders', async () => {
  const r = await render(<p title="Restart the mesh">The mesh is down</p>);
  await r.unmount();
});
