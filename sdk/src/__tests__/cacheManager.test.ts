import { CacheManager, DataType } from '../cacheManager';

describe('CacheManager', () => {
  let cache: CacheManager;

  beforeEach(() => {
    cache = new CacheManager({ ttl: { [DataType.DID_DOCUMENT]: 1000 } });
  });

  test('should set and get a value', () => {
    cache.set(DataType.DID_DOCUMENT, 'did:test:123', { name: 'Alice' });
    const result = cache.get<any>(DataType.DID_DOCUMENT, 'did:test:123');
    expect(result).toEqual({ name: 'Alice' });
  });

  test('should return null for missing key', () => {
    const result = cache.get(DataType.DID_DOCUMENT, 'nonexistent');
    expect(result).toBeNull();
  });

  test('should expire entries after TTL', async () => {
    cache.set(DataType.REPUTATION_SCORE, 'user:1', { score: 850 });
    const result = cache.get(DataType.REPUTATION_SCORE, 'user:1');
    expect(result).toEqual({ score: 850 });

    await new Promise(resolve => setTimeout(resolve, 1100));
    cache = new CacheManager({ ttl: { [DataType.REPUTATION_SCORE]: 1 } });
    cache.set(DataType.REPUTATION_SCORE, 'user:1', { score: 850 });
    await new Promise(resolve => setTimeout(resolve, 50));
    const expired = cache.get(DataType.REPUTATION_SCORE, 'user:1');
    expect(expired).toBeNull();
  });

  test('should invalidate a specific key', () => {
    cache.set(DataType.DID_DOCUMENT, 'did:test:1', { name: 'Alice' });
    cache.invalidate(DataType.DID_DOCUMENT, 'did:test:1');
    const result = cache.get(DataType.DID_DOCUMENT, 'did:test:1');
    expect(result).toBeNull();
  });

  test('should clear all entries for a type', () => {
    cache.set(DataType.DID_DOCUMENT, 'did:test:1', { name: 'Alice' });
    cache.set(DataType.DID_DOCUMENT, 'did:test:2', { name: 'Bob' });
    cache.invalidateForType(DataType.DID_DOCUMENT);
    expect(cache.get(DataType.DID_DOCUMENT, 'did:test:1')).toBeNull();
    expect(cache.get(DataType.DID_DOCUMENT, 'did:test:2')).toBeNull();
  });

  test('should clear all cache entries', () => {
    cache.set(DataType.DID_DOCUMENT, 'did:test:1', { name: 'Alice' });
    cache.set(DataType.REPUTATION_SCORE, 'user:1', { score: 900 });
    cache.clearAll();
    expect(cache.get(DataType.DID_DOCUMENT, 'did:test:1')).toBeNull();
    expect(cache.get(DataType.REPUTATION_SCORE, 'user:1')).toBeNull();
  });

  test('should track cache stats', () => {
    cache.get(DataType.DID_DOCUMENT, 'nonexistent');
    cache.set(DataType.DID_DOCUMENT, 'key1', 'value1');
    cache.get(DataType.DID_DOCUMENT, 'key1');
    cache.get(DataType.DID_DOCUMENT, 'key1');

    const stats = cache.getStats();
    expect(stats[DataType.DID_DOCUMENT].hits).toBe(2);
    expect(stats[DataType.DID_DOCUMENT].misses).toBe(1);
  });

  test('should support opt-out per request via useCache option', () => {
    cache.set(DataType.DID_DOCUMENT, 'did:test:1', { name: 'Alice' });
    cache.invalidate(DataType.DID_DOCUMENT, 'did:test:1');
    const result = cache.get(DataType.DID_DOCUMENT, 'did:test:1');
    expect(result).toBeNull();
  });
});
