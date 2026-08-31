import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { AccordLockProject } from '../../acp/projects';
import { IntlTestWrapper } from '../../i18n/test-utils';
import { ProjectPicker } from './ProjectPicker';

function project(overrides: Partial<AccordLockProject> = {}): AccordLockProject {
  return {
    id: 'website-launch',
    title: 'Website launch',
    description: '',
    instructions: '',
    workingDirs: ['C:\\Work\\Website'],
    archived: false,
    color: '#6366F1',
    sourcePath: 'projects/website-launch.md',
    writable: true,
    properties: { title: 'Website launch', workingDirs: ['C:\\Work\\Website'] },
    ...overrides,
  };
}

beforeAll(() => {
  Object.defineProperty(globalThis.Element.prototype, 'hasPointerCapture', {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(globalThis.Element.prototype, 'setPointerCapture', {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(globalThis.Element.prototype, 'releasePointerCapture', {
    configurable: true,
    value: vi.fn(),
  });
});

describe('ProjectPicker', () => {
  it('changes the selected project from one compact menu', async () => {
    const onChange = vi.fn();
    const website = project();
    const research = project({ id: 'research', title: 'Research', color: '#0F766E' });
    const user = userEvent.setup();

    render(
      <ProjectPicker
        projects={[website, research]}
        selectedProjectId={website.id}
        onChange={onChange}
      />,
      { wrapper: IntlTestWrapper }
    );

    await user.click(screen.getByRole('button', { name: 'Project: Website launch' }));
    await user.click(screen.getByRole('menuitemradio', { name: 'Research' }));

    expect(onChange).toHaveBeenCalledWith('research');
  });

  it('lets the user explicitly leave a task outside projects', async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();

    render(
      <ProjectPicker
        projects={[project()]}
        selectedProjectId="website-launch"
        onChange={onChange}
      />,
      { wrapper: IntlTestWrapper }
    );

    await user.click(screen.getByRole('button', { name: 'Project: Website launch' }));
    await user.click(screen.getByRole('menuitemradio', { name: 'No project' }));

    expect(onChange).toHaveBeenCalledWith(null);
  });

  it('offers to create the first active project', async () => {
    const onCreateProject = vi.fn();
    const user = userEvent.setup();

    render(
      <ProjectPicker
        projects={[project({ archived: true })]}
        selectedProjectId={null}
        onChange={() => undefined}
        onCreateProject={onCreateProject}
      />,
      { wrapper: IntlTestWrapper }
    );

    await user.click(screen.getByRole('button', { name: 'Create project' }));

    expect(onCreateProject).toHaveBeenCalledOnce();
  });
});
