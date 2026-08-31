import { describe, expect, it } from 'vitest';
import {
  findSupportedDeepLink,
  isSupportedDeepLink,
  isSupportedDeepLinkProtocol,
} from './deepLinks';

describe('AccordLock deep links', () => {
  it('accepts only AccordLock links', () => {
    expect(isSupportedDeepLink('accordlock://recipe?config=abc', 'recipe?config=')).toBe(true);
    expect(isSupportedDeepLink('goose://recipe?config=abc', 'recipe?config=')).toBe(false);
    expect(isSupportedDeepLink('https://example.com/recipe?config=abc')).toBe(false);
  });

  it('finds a supported link in process arguments', () => {
    expect(
      findSupportedDeepLink(['AccordLock.exe', '--flag', 'accordlock://new-session?prompt=hello'])
    ).toBe('accordlock://new-session?prompt=hello');
  });

  it('accepts only the AccordLock protocol', () => {
    expect(isSupportedDeepLinkProtocol('accordlock:')).toBe(true);
    expect(isSupportedDeepLinkProtocol('goose:')).toBe(false);
    expect(isSupportedDeepLinkProtocol('file:')).toBe(false);
  });
});
