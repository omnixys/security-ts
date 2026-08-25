import { extractEventId } from '../dist/index.js';
import assert from 'node:assert/strict';
import test from 'node:test';

test('extractEventId prefers GraphQL variables over activeEvent cookie', () => {
  const result = extractEventId({
    body: {
      variables: {
        eventId: 'event-from-vars',
      },
    },
    headers: {
      cookie: `activeEvent=${encodeURIComponent(JSON.stringify({ id: 'event-from-cookie' }))}`,
    },
  });

  assert.equal(result, 'event-from-vars');
});

test('extractEventId ignores a resource id and uses the active event cookie', () => {
  const result = extractEventId({
    body: {
      variables: {
        id: 'invitation-id',
      },
    },
    headers: {
      cookie: `activeEvent=${encodeURIComponent(JSON.stringify({ id: 'event-from-cookie' }))}`,
    },
  });

  assert.equal(result, 'event-from-cookie');
});

test('extractEventId does not treat a resource id as an event id', () => {
  const result = extractEventId({
    body: {
      variables: {
        id: 'invitation-id',
      },
    },
  });

  assert.equal(result, null);
});

test('extractEventId reads event ids from input and filter variables', () => {
  assert.equal(
    extractEventId({
      body: { variables: { input: { eventId: 'event-from-input' } } },
    }),
    'event-from-input',
  );

  assert.equal(
    extractEventId({
      body: { variables: { filter: { eventId: 'event-from-filter' } } },
    }),
    'event-from-filter',
  );
});

test('extractEventId reads encoded activeEvent JSON cookie', () => {
  const result = extractEventId({
    body: { variables: {} },
    headers: {
      cookie: `theme=dark; activeEvent=${encodeURIComponent(JSON.stringify({ id: 'event-1' }))}`,
    },
  });

  assert.equal(result, 'event-1');
});

test('extractEventId reads parsed activeEvent JSON cookie', () => {
  const result = extractEventId({
    body: { variables: {} },
    cookies: {
      activeEvent: JSON.stringify({ id: 'event-2' }),
    },
  });

  assert.equal(result, 'event-2');
});

test('extractEventId ignores malformed activeEvent cookie', () => {
  const result = extractEventId({
    body: { variables: {} },
    headers: {
      cookie: 'activeEvent=%7Bbad-json',
    },
  });

  assert.equal(result, null);
});
