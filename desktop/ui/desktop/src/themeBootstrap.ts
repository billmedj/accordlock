function preferredDarkTheme(): boolean {
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const useSystemTheme = localStorage.getItem('use_system_theme') === 'true';
  const savedTheme = localStorage.getItem('theme');
  return useSystemTheme
    ? systemPrefersDark
    : savedTheme
      ? savedTheme === 'dark'
      : systemPrefersDark;
}

function applyInitialTheme(): void {
  try {
    const dark = preferredDarkTheme();
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
  } catch {
    const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
  }
}

applyInitialTheme();
