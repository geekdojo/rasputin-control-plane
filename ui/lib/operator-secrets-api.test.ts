import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ApiError, deployApp, errorSentence, listAppSecrets, setAppSecret } from './api';
import { listFailureText } from './operator-secrets';

// geekdojo/geekdojo-brain#781: the two #604 routes as the UI calls them, and
// the jsonFetch change behind ApiError.sentence, against a stubbed fetch.

const SENTINEL = 'Qz7Xv9Kj4W';
const APP = '01JAPPID0000000000000000AB';

interface Seen {
  url: string;
  init: RequestInit;
}

function reply(status: number, body?: unknown, raw?: string): Response {
  const text = raw ?? (body === undefined ? '' : JSON.stringify(body));
  return new Response(status === 204 ? null : text, {
    status,
    headers: raw === undefined ? { 'Content-Type': 'application/json' } : { 'Content-Type': 'text/plain' },
  });
}

// withFetch stubs globalThis.fetch for one call and always restores it.
async function withFetch<T>(answer: () => Response | Promise<Response>, run: (seen: Seen[]) => Promise<T>): Promise<T> {
  const real = globalThis.fetch;
  const seen: Seen[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push({ url: String(input), init: init ?? {} });
    return answer();
  }) as typeof fetch;
  try {
    return await run(seen);
  } finally {
    globalThis.fetch = real;
  }
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  assert.fail('expected the call to throw');
}

describe('setAppSecret', () => {
  // TC-781-12
  test('PUTs the value in the body only, with the session cookie', async () => {
    await withFetch(
      () => reply(204),
      async (seen) => {
        const got = await setAppSecret('01J/…', 'feed-key', SENTINEL);
        assert.equal(got, undefined);
        assert.equal(seen.length, 1);
        assert.equal(seen[0].url, `/api/apps/${encodeURIComponent('01J/…')}/secrets/feed-key`);
        assert.ok(!seen[0].url.includes(SENTINEL));
        assert.equal(seen[0].init.method, 'PUT');
        assert.equal(seen[0].init.credentials, 'include');
        assert.deepEqual(seen[0].init.headers, { 'Content-Type': 'application/json' });
        assert.equal(seen[0].init.body, `{"value":"${SENTINEL}"}`);
      },
    );
  });

  test('the name is encoded too', async () => {
    await withFetch(
      () => reply(204),
      async (seen) => {
        await setAppSecret(APP, 'a b', SENTINEL);
        assert.equal(seen[0].url, `/api/apps/${APP}/secrets/a%20b`);
      },
    );
  });

  // TC-781-13
  const S1 =
    'The value was refused. It must not be empty, must not contain a NUL byte, and must not be a date and time in RFC 3339 form.';
  const S2 = 'The secret store could not save the value. The api log names the cause.';
  for (const [status, body, sentence] of [
    [400, { error: S1, code: 'secret_value_invalid' }, S1],
    [503, { error: S2, code: 'secret_store_unavailable' }, S2],
  ] as const) {
    test(`a ${status} refusal is the api's sentence`, async () => {
      const e = await withFetch(
        () => reply(status, body),
        () => rejection(setAppSecret(APP, 'feed-key', SENTINEL)),
      );
      assert.ok(e instanceof ApiError);
      assert.equal(e.status, status);
      assert.equal(e.sentence, sentence);
      assert.equal(e.message, sentence);
      assert.equal(errorSentence(e, 'fallback'), sentence);
      assert.ok(!e.message.includes('/api/') && !e.message.includes(SENTINEL));
    });
  }

  test('a non-JSON refusal is a fixed sentence with the status', async () => {
    const e = await withFetch(
      () => reply(500, undefined, '<html>oops</html>'),
      () => rejection(setAppSecret(APP, 'feed-key', SENTINEL)),
    );
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 500);
    assert.equal(errorSentence(e, 'fallback'), 'The secret could not be saved (HTTP 500).');
    assert.ok(!e.message.includes('/api/') && !e.message.includes(SENTINEL));
  });

  test('a network failure throws, and its on-screen text is the fallback', async () => {
    const e = await withFetch(
      () => Promise.reject(new TypeError('Failed to fetch')),
      () => rejection(setAppSecret(APP, 'feed-key', SENTINEL)),
    );
    assert.ok(e instanceof TypeError);
    assert.equal(errorSentence(e, 'The secret could not be saved.'), 'The secret could not be saved.');
    assert.ok(!String(e).includes(SENTINEL));
  });
});

describe('listAppSecrets', () => {
  // TC-781-14
  const two = [
    { name: 'feed-key', label: 'Feed key', required: true, set: false },
    { name: 'map-key', label: 'Map key', required: false, set: true },
  ];

  test('GETs the list with the session cookie and returns it unchanged', async () => {
    await withFetch(
      () => reply(200, two),
      async (seen) => {
        assert.deepEqual(await listAppSecrets(APP), two);
        assert.equal(seen[0].url, `/api/apps/${APP}/secrets`);
        assert.equal(seen[0].init.method ?? 'GET', 'GET');
        assert.equal(seen[0].init.credentials, 'include');
      },
    );
  });

  test('null is an empty list', async () => {
    await withFetch(
      () => reply(200, null),
      async () => assert.deepEqual(await listAppSecrets(APP), []),
    );
  });

  test("a refusal's on-screen text is the api's sentence alone", async () => {
    const S = "The app's secrets could not be listed. The api log names the cause.";
    const e = await withFetch(
      () => reply(500, { error: S }),
      () => rejection(listAppSecrets(APP)),
    );
    assert.ok(e instanceof ApiError);
    assert.equal(e.sentence, S);
    const text = listFailureText(e);
    assert.equal(text, S);
    assert.ok(!text.includes('/api/'));
    assert.equal(text.split(S).length - 1, 1, 'the sentence appears once');
  });

  test('a network failure is a fixed sentence', async () => {
    const e = await withFetch(
      () => Promise.reject(new TypeError('Failed to fetch')),
      () => rejection(listAppSecrets(APP)),
    );
    assert.equal(listFailureText(e), "This app's secrets could not be listed.");
  });
});

describe('jsonFetch, for existing callers', () => {
  // TC-781-15: every String(e) caller renders what it did before #781.
  test('a refusal with a sentence keeps the URL-and-status message', async () => {
    const e = await withFetch(
      () => reply(400, { error: 'x' }),
      () => rejection(deployApp('A')),
    );
    assert.ok(e instanceof ApiError);
    assert.equal(e.message, '/api/apps/A/deploy → 400: x');
    assert.equal(e.status, 400);
    assert.equal(e.sentence, 'x');
  });

  test('a refusal with no JSON body keeps the bare URL-and-status message', async () => {
    const e = await withFetch(
      () => reply(502, undefined, 'Bad Gateway'),
      () => rejection(deployApp('A')),
    );
    assert.ok(e instanceof ApiError);
    assert.equal(e.message, '/api/apps/A/deploy → 502');
    assert.equal(e.status, 502);
    assert.equal(e.sentence, undefined);
    assert.equal(errorSentence(e, 'fallback'), 'fallback');
  });
});
