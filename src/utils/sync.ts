type Fn<T> = () => Promise<T>;
type SingleflightEntry<T> = { promise: Promise<T>; dups: number };

export class Singleflight {
  private inflight = new Map<string, SingleflightEntry<unknown>>();

  async do<T>(key: string, fn: Fn<T>): Promise<{ value: T; shared: boolean }> {
    const existing = this.inflight.get(key) as SingleflightEntry<T> | undefined;

    if (existing) {
      existing.dups += 1;
      const value = await existing.promise;
      return { value, shared: true };
    }

    const entry: SingleflightEntry<T> = { promise: Promise.resolve().then(fn), dups: 0 };
    this.inflight.set(key, entry as SingleflightEntry<unknown>);

    try {
      const value = await entry.promise;
      return { value, shared: entry.dups > 0 };
    } finally {
      if (this.inflight.get(key) === (entry as SingleflightEntry<unknown>)) {
        this.inflight.delete(key);
      }
    }
  }

  forget(key: string): void {
    this.inflight.delete(key);
  }
}
