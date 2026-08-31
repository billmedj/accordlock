const assert = require('node:assert/strict');
const test = require('node:test');

const { assertNoWindowsUserProfile, replaceAllExact } = require('./sanitize-windows-build-paths');

test('replaceAllExact preserves offsets for ASCII and UTF-16LE paths', () => {
  const original = 'C:\\Users\\builder\\';
  const replacement = 'C:\\build\\release\\';
  assert.equal(original.length, replacement.length);

  const ascii = Buffer.from(`${original}one ${original}two`, 'utf8');
  assert.equal(
    replaceAllExact(ascii, Buffer.from(original, 'utf8'), Buffer.from(replacement, 'utf8')),
    2
  );
  assert.equal(ascii.toString('utf8'), `${replacement}one ${replacement}two`);

  const utf16 = Buffer.from(`${original}one`, 'utf16le');
  assert.equal(
    replaceAllExact(utf16, Buffer.from(original, 'utf16le'), Buffer.from(replacement, 'utf16le')),
    1
  );
  assert.equal(utf16.toString('utf16le'), `${replacement}one`);
});

test('replaceAllExact refuses a replacement that could shift binary offsets', () => {
  assert.throws(
    () => replaceAllExact(Buffer.from('abc'), Buffer.from('a'), Buffer.from('longer')),
    /same non-zero byte length/
  );
});

test('profile-path assertion checks ASCII and UTF-16LE data', () => {
  assert.doesNotThrow(() =>
    assertNoWindowsUserProfile(Buffer.from('C:\\build\\source'), 'fixture')
  );
  assert.throws(
    () => assertNoWindowsUserProfile(Buffer.from('C:\\Users\\builder\\source'), 'fixture'),
    /still contains/
  );
  assert.throws(
    () =>
      assertNoWindowsUserProfile(Buffer.from('C:\\Users\\builder\\source', 'utf16le'), 'fixture'),
    /still contains/
  );
});
