import { ChatState } from '../types/chatState';
import { defineMessages, useIntl } from '../i18n';
import { AccordLockGlyph } from './accordlock/AccordLockBrand';

interface LoadingGooseProps {
  message?: string;
  chatState?: ChatState;
}

const i18n = defineMessages({
  loadingConversation: {
    id: 'loadingGoose.loadingConversation',
    defaultMessage: 'Preparing your task…',
  },
  thinking: {
    id: 'loadingGoose.thinking',
    defaultMessage: 'Thinking…',
  },
  streaming: {
    id: 'loadingGoose.streaming',
    defaultMessage: 'Working…',
  },
  waiting: {
    id: 'loadingGoose.waiting',
    defaultMessage: 'Waiting for you…',
  },
  compacting: {
    id: 'loadingGoose.compacting',
    defaultMessage: 'Organizing context…',
  },
  idle: {
    id: 'loadingGoose.idle',
    defaultMessage: 'Ready',
  },
  restartingAgent: {
    id: 'loadingGoose.restartingAgent',
    defaultMessage: 'Reconnecting…',
  },
});

const STATE_MESSAGE_KEYS: Record<ChatState, keyof typeof i18n> = {
  [ChatState.LoadingConversation]: 'loadingConversation',
  [ChatState.Thinking]: 'thinking',
  [ChatState.Streaming]: 'streaming',
  [ChatState.WaitingForUserInput]: 'waiting',
  [ChatState.Compacting]: 'compacting',
  [ChatState.Idle]: 'idle',
  [ChatState.RestartingAgent]: 'restartingAgent',
};

const LoadingGoose = ({ message, chatState = ChatState.Idle }: LoadingGooseProps) => {
  const intl = useIntl();
  const displayMessage = message || intl.formatMessage(i18n[STATE_MESSAGE_KEYS[chatState]]);
  const active = chatState !== ChatState.Idle && chatState !== ChatState.WaitingForUserInput;

  return (
    <div className="w-full animate-fade-slide-up">
      <div
        data-testid="loading-indicator"
        role="status"
        aria-live="polite"
        className="flex items-center gap-2.5 py-2 text-xs text-text-secondary"
      >
        <AccordLockGlyph busy={active} className="size-6 rounded-lg shadow-none" />
        <span>{displayMessage}</span>
      </div>
    </div>
  );
};

export default LoadingGoose;
