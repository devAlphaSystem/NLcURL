/**
 * Represents a named group of cache keys for batch invalidation.
 */
export interface CacheGroup {
  name: string;
  keys: Set<string>;
  lastInvalidated: number;
}

/**
 * Parses a comma-separated Cache-Groups header into an array of group names.
 *
 * @param {string} header - The raw Cache-Groups header value.
 * @returns {string[]} Parsed group names.
 */
export function parseCacheGroups(header: string): string[] {
  if (!header) return [];
  return header
    .split(",")
    .map((s) => s.trim().replace(/"/g, ""))
    .filter(Boolean);
}

/**
 * Manages cache key groupings for targeted invalidation of related cache entries.
 *
 * @class
 */
export class CacheGroupStore {
  private readonly groups = new Map<string, CacheGroup>();

  /**
   * Associates a cache key with one or more named groups.
   *
   * @param {string} cacheKey - The cache key to associate.
   * @param {string[]} groupNames - The groups to add the key to.
   */
  addToGroups(cacheKey: string, groupNames: string[]): void {
    for (const name of groupNames) {
      let group = this.groups.get(name);
      if (!group) {
        group = { name, keys: new Set(), lastInvalidated: 0 };
        this.groups.set(name, group);
      }
      group.keys.add(cacheKey);
    }
  }

  /**
   * Removes a cache key from all groups.
   *
   * @param {string} cacheKey - The cache key to remove.
   */
  removeFromAll(cacheKey: string): void {
    for (const group of this.groups.values()) {
      group.keys.delete(cacheKey);
    }
  }

  /**
   * Returns the set of cache keys belonging to a specific group.
   *
   * @param {string} groupName - The group name.
   * @returns {Set<string>} The cache keys in the group.
   */
  getGroupKeys(groupName: string): Set<string> {
    return this.groups.get(groupName)?.keys ?? new Set();
  }

  /**
   * Invalidates a single group, clearing its keys and recording the timestamp.
   *
   * @param {string} groupName - The group name to invalidate.
   * @returns {string[]} The cache keys that were in the invalidated group.
   */
  invalidate(groupName: string): string[] {
    const group = this.groups.get(groupName);
    if (!group) return [];

    const keys = [...group.keys];
    group.keys.clear();
    group.lastInvalidated = Date.now();
    return keys;
  }

  /**
   * Invalidates all groups, clearing their keys and recording the timestamp.
   *
   * @returns {string[]} All unique cache keys that were invalidated.
   */
  invalidateAll(): string[] {
    const allKeys = new Set<string>();
    for (const group of this.groups.values()) {
      for (const key of group.keys) {
        allKeys.add(key);
      }
      group.keys.clear();
      group.lastInvalidated = Date.now();
    }
    return [...allKeys];
  }

  /**
   * Checks whether a cache key has been invalidated since a given timestamp.
   *
   * @param {string} cacheKey - The cache key to check.
   * @param {number} storedAt - The timestamp when the entry was stored.
   * @returns {boolean} `true` if the key was invalidated after `storedAt`.
   */
  isInvalidatedSince(cacheKey: string, storedAt: number): boolean {
    for (const group of this.groups.values()) {
      if (group.keys.has(cacheKey) && group.lastInvalidated > storedAt) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns the number of tracked groups.
   *
   * @returns {number} The group count.
   */
  get size(): number {
    return this.groups.size;
  }

  /**
   * Removes all groups and their key associations.
   */
  clear(): void {
    this.groups.clear();
  }
}
