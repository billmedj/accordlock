import type { TaskControlProjection } from '../../accordlock/intentControl';
import { cn } from '../../utils';

function taskControlClasses(status: TaskControlProjection['status']): string {
  if (status === 'WITHIN_APPROVED_ACCESS') {
    return 'border-green-500/25 bg-green-500/10 text-green-700 dark:text-green-300';
  }
  if (status === 'REVIEWED') {
    return 'border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300';
  }
  return 'border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300';
}

export function TaskControlBadge({ value }: { value: TaskControlProjection }) {
  return (
    <span
      aria-label={`${value.label}: ${value.reason}`}
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
        taskControlClasses(value.status),
        value.provenance === 'RECONSTRUCTED' && 'border-dashed opacity-80'
      )}
      title={value.reason}
    >
      {value.label}
    </span>
  );
}
