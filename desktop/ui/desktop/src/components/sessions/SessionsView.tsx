// Modified by AccordLock contributors; see UPSTREAM.md.
import React, { useCallback } from 'react';
import SessionListView from './SessionListView';
import { useNavigation } from '../../hooks/useNavigation';
import { useSearchParams } from 'react-router';

const SessionsView: React.FC = () => {
  const setView = useNavigation();
  const [searchParams, setSearchParams] = useSearchParams();
  const projectId = searchParams.get('projectId') ?? undefined;

  const handleSelectSession = useCallback(
    async (sessionId: string) => {
      setView('pair', {
        disableAnimation: true,
        resumeSessionId: sessionId,
      });
    },
    [setView]
  );

  const clearProjectFilter = useCallback(() => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete('projectId');
      return next;
    });
  }, [setSearchParams]);

  return (
    <SessionListView
      onSelectSession={handleSelectSession}
      projectId={projectId}
      onClearProjectFilter={clearProjectFilter}
    />
  );
};

export default SessionsView;
