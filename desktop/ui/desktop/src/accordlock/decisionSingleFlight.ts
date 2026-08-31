import type { AccordLockTaskAuthorizationDecision } from './taskIpc';

interface DecisionFlight {
  decision: AccordLockTaskAuthorizationDecision;
  promise: Promise<unknown>;
}

/** Coalesces identical native-review flows and rejects contradictory races. */
export class AccordLockDecisionSingleFlight {
  private readonly flights = new Map<string, DecisionFlight>();

  run<T>(
    reviewId: string,
    decision: AccordLockTaskAuthorizationDecision,
    operation: () => Promise<T>
  ): Promise<T> {
    const existing = this.flights.get(reviewId);
    if (existing) {
      if (existing.decision !== decision) {
        return Promise.reject(
          new Error('Task already has a different authorization decision in progress')
        );
      }
      return existing.promise as Promise<T>;
    }

    const promise = Promise.resolve().then(operation);
    this.flights.set(reviewId, { decision, promise });
    const release = () => {
      if (this.flights.get(reviewId)?.promise === promise) {
        this.flights.delete(reviewId);
      }
    };
    void promise.then(release, release);
    return promise;
  }
}
