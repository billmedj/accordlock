import { cn } from '../../utils';

interface AccordLockMarkProps {
  className?: string;
  busy?: boolean;
}

/**
 * AccordLock's verified-handoff mark: intent and execution meet at one
 * controlled transaction point before either flow can continue.
 */
export function AccordLockMark({ className, busy = false }: AccordLockMarkProps) {
  return (
    <svg
      aria-hidden="true"
      className={cn('size-[22px]', className)}
      data-accordlock-mark="verified-handoff"
      fill="none"
      viewBox="0 0 32 32"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M25 11.1875H19.8125C17.5 11.1875 16 12.6875 16 15V17C16 19.3125 14.5 20.8125 12.1875 20.8125H7"
        stroke="#7E8492"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2.4375"
      />
      <path
        d="M7 11.1875H12.1875C14.5 11.1875 16 12.6875 16 15V17C16 19.3125 17.5 20.8125 19.8125 20.8125H25"
        stroke="#F4F1E9"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2.4375"
      />
      <rect
        className={busy ? 'motion-safe:animate-pulse' : undefined}
        x="13.9375"
        y="13.9375"
        width="4.125"
        height="4.125"
        rx="1.125"
        fill="#5264E8"
      />
    </svg>
  );
}

interface AccordLockGlyphProps {
  className?: string;
  active?: boolean;
  busy?: boolean;
}

export function AccordLockGlyph({ className, active = false, busy = false }: AccordLockGlyphProps) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'relative inline-grid size-8 shrink-0 place-items-center rounded-[10px]',
        'bg-[#111318] shadow-sm ring-1 ring-inset ring-white/[0.08]',
        className
      )}
    >
      <AccordLockMark busy={busy} className="size-[70%]" />
      {active && (
        <span
          className="absolute -bottom-0.5 -right-0.5 size-2.5 rounded-full border-2 border-background-primary bg-green-500"
          data-accordlock-status="active"
        />
      )}
    </span>
  );
}

interface AccordLockWordmarkProps extends AccordLockGlyphProps {
  subtitle?: string;
}

export function AccordLockWordmark({ className, active, busy, subtitle }: AccordLockWordmarkProps) {
  return (
    <div className={cn('inline-flex min-w-0 select-none items-center gap-2.5', className)}>
      <AccordLockGlyph active={active} busy={busy} />
      <div className="min-w-0 leading-none">
        <div className="truncate text-[15px] font-semibold tracking-[-0.035em] text-text-primary">
          AccordLock
        </div>
        {subtitle && (
          <div className="mt-1 truncate text-[10px] font-medium tracking-[0.02em] text-text-tertiary">
            {subtitle}
          </div>
        )}
      </div>
    </div>
  );
}
