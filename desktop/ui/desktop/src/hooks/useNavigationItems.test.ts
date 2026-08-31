import { describe, expect, it } from 'vitest';
import { NAV_ITEMS } from './useNavigationItems';

describe('AccordLock navigation', () => {
  it('exposes only product surfaces backed by the protected distribution', () => {
    expect(NAV_ITEMS.map((item) => item.id)).toEqual([
      'home',
      'approvals',
      'projects',
      'sessions',
      'audit',
      'recipes',
    ]);
    expect(NAV_ITEMS.map((item) => item.label)).toEqual([
      'New task',
      'Approvals',
      'Projects',
      'Tasks',
      'Audit',
      'Playbooks',
    ]);
    expect(NAV_ITEMS.map((item) => item.id)).not.toEqual(
      expect.arrayContaining(['apps', 'scheduler', 'extensions', 'skills'])
    );
  });
});
