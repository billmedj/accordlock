import { describe, expect, it } from 'vitest';
import type { FixedExtensionEntry } from '../components/ConfigContext';
import { selectAccordLockTaskExtensions } from './taskExtensions';

function extension(name: string, enabled: boolean): FixedExtensionEntry {
  return {
    name,
    enabled,
    type: 'builtin',
    description: `${name} extension`,
  };
}

describe('selectAccordLockTaskExtensions', () => {
  it('loads only the filesystem extension covered by the task contract', () => {
    expect(
      selectAccordLockTaskExtensions([
        extension('memory', true),
        extension('developer', true),
        extension('computercontroller', true),
      ])
    ).toEqual([
      {
        name: 'developer',
        type: 'builtin',
        description: 'developer extension',
      },
    ]);
  });

  it('does not let a global toggle remove the protected filesystem engine', () => {
    expect(selectAccordLockTaskExtensions([extension('developer', false)])).toHaveLength(1);
  });

  it('fails closed when the packaged filesystem engine is unavailable', () => {
    expect(selectAccordLockTaskExtensions([extension('memory', true)])).toEqual([]);
  });
});
