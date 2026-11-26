package com.keyvault.service;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class RateLimiterService {

    private static final long WINDOW_SECONDS = 60;
    private static final int CLEANUP_INTERVAL_OPS = 256;

    private final Map<Long, Deque<Long>> keyRequestTimestamps = new ConcurrentHashMap<>();
    private final AtomicLong operationCounter = new AtomicLong();
    private final Clock clock;

    @Autowired
    public RateLimiterService() {
        this(Clock.systemUTC());
    }

    RateLimiterService(Clock clock) {
        this.clock = clock;
    }

    @Getter
    @AllArgsConstructor
    public static class RateLimitResult {
        private final boolean allowed;
        private final int limit;
        private final int remaining;
        private final long resetSeconds;
    }

    /**
     * Checks and consumes one request slot within the sliding 60-second window for {@code apiKeyId}.
     * Synchronizes atomically per key bucket via {@link ConcurrentHashMap#compute} rather than
     * locking globally across all keys.
     */
    public RateLimitResult checkAndConsume(Long apiKeyId, int limitPerMinute) {
        if (limitPerMinute <= 0) {
            return new RateLimitResult(true, limitPerMinute, limitPerMinute, 0);
        }

        long now = clock.instant().getEpochSecond();
        if (operationCounter.incrementAndGet() % CLEANUP_INTERVAL_OPS == 0) {
            evictStaleEntries();
        }

        long windowStart = now - WINDOW_SECONDS;
        AtomicReference<RateLimitResult> resultRef = new AtomicReference<>();

        keyRequestTimestamps.compute(apiKeyId, (id, existing) -> {
            Deque<Long> timestamps = existing != null ? existing : new ArrayDeque<>();
            evictExpiredTimestamps(timestamps, windowStart);

            int currentCount = timestamps.size();
            long oldestTimestamp = timestamps.isEmpty() ? now : timestamps.peekFirst();
            long resetSeconds = Math.max(1, (oldestTimestamp + WINDOW_SECONDS) - now);

            if (currentCount >= limitPerMinute) {
                resultRef.set(new RateLimitResult(false, limitPerMinute, 0, resetSeconds));
                return timestamps.isEmpty() ? null : timestamps;
            }

            timestamps.addLast(now);
            int remaining = Math.max(0, limitPerMinute - (currentCount + 1));
            resultRef.set(new RateLimitResult(true, limitPerMinute, remaining, resetSeconds));
            return timestamps;
        });

        return resultRef.get();
    }

    /**
     * Removes key buckets whose timestamps have all fallen outside the active sliding window,
     * preventing unbounded map growth when keys become idle or are deleted.
     *
     * @return number of stale key buckets removed
     */
    public int evictStaleEntries() {
        long windowStart = clock.instant().getEpochSecond() - WINDOW_SECONDS;
        int removed = 0;

        for (Long keyId : keyRequestTimestamps.keySet()) {
            AtomicBoolean wasRemoved = new AtomicBoolean(false);
            keyRequestTimestamps.computeIfPresent(keyId, (id, timestamps) -> {
                evictExpiredTimestamps(timestamps, windowStart);
                if (timestamps.isEmpty()) {
                    wasRemoved.set(true);
                    return null;
                }
                return timestamps;
            });
            if (wasRemoved.get()) {
                removed++;
            }
        }
        return removed;
    }

    public void clear(Long apiKeyId) {
        keyRequestTimestamps.remove(apiKeyId);
    }

    int getTrackedKeyCount() {
        return keyRequestTimestamps.size();
    }

    private static void evictExpiredTimestamps(Deque<Long> timestamps, long windowStart) {
        while (!timestamps.isEmpty() && timestamps.peekFirst() <= windowStart) {
            timestamps.pollFirst();
        }
    }
}
