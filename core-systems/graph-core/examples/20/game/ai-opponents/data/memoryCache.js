/**
 * memoryCache.js
 * Промышленный модуль кратковременной памяти ИИ-персонажей.
 * Используется для хранения последних наблюдений, событий, угроз, путей и команд.
 * Поддерживает временной TTL, индексацию по типу и приоритету, эвристическую вытеснение.
 */

class MemoryEntry {
  constructor({ type, payload, timestamp = Date.now(), ttl = 5000, priority = 1.0, tags = [] }) {
    this.id = crypto.randomUUID();
    this.type = type;               // eg. 'threat', 'sound', 'ally_call'
    this.payload = payload;         // arbitrary object (position, entity, value)
    this.timestamp = timestamp;     // ms since epoch
    this.ttl = ttl;                 // time to live (ms)
    this.priority = priority;       // float 0.0 – 1.0
    this.tags = new Set(tags);      // eg. ['combat', 'player']
  }

  isExpired(currentTime = Date.now()) {
    return (currentTime - this.timestamp) > this.ttl;
  }
}

export class MemoryCache {
  constructor(maxSize = 200) {
    this.maxSize = maxSize;
    this.entries = new Map();     // key: entry.id, value: MemoryEntry
    this.typeIndex = new Map();   // key: type, value: Set of ids
    this.tagIndex = new Map();    // key: tag, value: Set of ids
  }

  insert(entryData) {
    const entry = new MemoryEntry(entryData);

    // Eviction if needed
    if (this.entries.size >= this.maxSize) {
      this.evict();
    }

    this.entries.set(entry.id, entry);

    // Index by type
    if (!this.typeIndex.has(entry.type)) this.typeIndex.set(entry.type, new Set());
    this.typeIndex.get(entry.type).add(entry.id);

    // Index by tags
    for (const tag of entry.tags) {
      if (!this.tagIndex.has(tag)) this.tagIndex.set(tag, new Set());
      this.tagIndex.get(tag).add(entry.id);
    }

    return entry.id;
  }

  evict() {
    const now = Date.now();
    const expiredIds = [];

    for (const [id, entry] of this.entries.entries()) {
      if (entry.isExpired(now)) expiredIds.push(id);
    }

    // If expired entries found — delete them
    if (expiredIds.length > 0) {
      for (const id of expiredIds) this.delete(id);
      return;
    }

    // Else: evict lowest-priority
    let lowest = null;
    for (const [id, entry] of this.entries.entries()) {
      if (!lowest || entry.priority < lowest.priority) {
        lowest = entry;
      }
    }
    if (lowest) this.delete(lowest.id);
  }

  delete(id) {
    const entry = this.entries.get(id);
    if (!entry) return;

    this.entries.delete(id);

    // Update type index
    if (this.typeIndex.has(entry.type)) {
      this.typeIndex.get(entry.type).delete(id);
      if (this.typeIndex.get(entry.type).size === 0) this.typeIndex.delete(entry.type);
    }

    // Update tag index
    for (const tag of entry.tags) {
      if (this.tagIndex.has(tag)) {
        this.tagIndex.get(tag).delete(id);
        if (this.tagIndex.get(tag).size === 0) this.tagIndex.delete(tag);
      }
    }
  }

  queryByType(type) {
    const ids = this.typeIndex.get(type) || new Set();
    return [...ids].map(id => this.entries.get(id));
  }

  queryByTag(tag) {
    const ids = this.tagIndex.get(tag) || new Set();
    return [...ids].map(id => this.entries.get(id));
  }

  queryRecent({ type = null, tag = null, sinceMs = 1000 }) {
    const now = Date.now();
    const all = type
      ? this.queryByType(type)
      : tag
      ? this.queryByTag(tag)
      : Array.from(this.entries.values());

    return all.filter(entry => (now - entry.timestamp) <= sinceMs);
  }

  cleanup() {
    const now = Date.now();
    for (const [id, entry] of this.entries.entries()) {
      if (entry.isExpired(now)) this.delete(id);
    }
  }

  toDebugJSON() {
    return JSON.stringify(
      Array.from(this.entries.values()).map(e => ({
        id: e.id,
        type: e.type,
        ageMs: Date.now() - e.timestamp,
        ttl: e.ttl,
        tags: Array.from(e.tags),
        priority: e.priority
      })),
      null,
      2
    );
  }
}
