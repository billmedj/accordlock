// Modified by AccordLock contributors; see UPSTREAM.md.
import { defineConfig, type Plugin } from 'vite';

const ALLOWED_SANDBOX_REQUIRE = 'electron';

function collectDisallowedRequires(value: unknown): Set<string> {
  const disallowed = new Set<string>();
  const visited = new Set<object>();

  const visit = (candidate: unknown) => {
    if (!candidate || typeof candidate !== 'object' || visited.has(candidate)) return;
    visited.add(candidate);

    const node = candidate as Record<string, unknown>;
    if (node.type === 'CallExpression') {
      const callee = node.callee as Record<string, unknown> | undefined;
      if (callee?.type === 'Identifier' && callee.name === 'require') {
        const args = Array.isArray(node.arguments) ? node.arguments : [];
        const firstArgument = args[0] as Record<string, unknown> | undefined;
        const specifier =
          args.length === 1 && firstArgument?.type === 'Literal'
            ? firstArgument.value
            : '<dynamic require>';
        if (specifier !== ALLOWED_SANDBOX_REQUIRE) {
          disallowed.add(typeof specifier === 'string' ? specifier : '<non-string require>');
        }
      }
    }

    for (const [key, child] of Object.entries(node)) {
      if (key !== 'parent') visit(child);
    }
  };

  visit(value);
  return disallowed;
}

function sandboxedPreloadGuard(): Plugin {
  return {
    name: 'accordlock-sandboxed-preload-guard',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const preload = bundle['preload.js'];
      if (!preload || preload.type !== 'chunk') {
        this.error('The sandboxed preload build did not emit preload.js');
      }

      const disallowed = [...collectDisallowedRequires(this.parse(preload.code))].sort();
      if (disallowed.length > 0) {
        this.error(
          `Sandboxed preload.js contains unsupported require() calls: ${disallowed.join(', ')}`
        );
      }
    },
  };
}

// https://vitejs.dev/config
export default defineConfig({
  // Sandboxed Electron preload scripts can only require Electron's supported
  // built-ins. Bundle every application dependency into preload.js so imports
  // added through shared IPC contracts (for example zod validators) cannot be
  // emitted as runtime require(...) calls that would make the secure bridge fail.
  ssr: {
    noExternal: true,
  },
  plugins: [sandboxedPreloadGuard()],
  build: {
    ssr: true,
    outDir: '.vite/build',
    rollupOptions: {
      input: 'src/preload.ts',
      output: {
        format: 'cjs',
        entryFileNames: 'preload.js',
      },
      external: ['electron'],
    },
  },
});
