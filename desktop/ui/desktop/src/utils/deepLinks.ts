export const PRIMARY_DEEP_LINK_SCHEME = 'accordlock';
export const SUPPORTED_DEEP_LINK_SCHEMES = [PRIMARY_DEEP_LINK_SCHEME] as const;

export function isSupportedDeepLink(url: string, route = ''): boolean {
  return SUPPORTED_DEEP_LINK_SCHEMES.some((scheme) => url.startsWith(`${scheme}://${route}`));
}

export function findSupportedDeepLink(args: string[]): string | undefined {
  return args.find((arg) => isSupportedDeepLink(arg));
}

export function isSupportedDeepLinkProtocol(protocol: string): boolean {
  return SUPPORTED_DEEP_LINK_SCHEMES.some((scheme) => protocol === `${scheme}:`);
}
