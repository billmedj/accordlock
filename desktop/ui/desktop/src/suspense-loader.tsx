// Modified by AccordLock contributors; see UPSTREAM.md.
import { AccordLockWordmark } from './components/accordlock/AccordLockBrand';

export default function SuspenseLoader() {
  return (
    <div className="flex flex-col items-start justify-end w-screen h-screen overflow-hidden p-6 page-transition">
      <AccordLockWordmark subtitle="Starting protected workspace" />
    </div>
  );
}
