package com.keyvault.service;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimiterService {

    private static final long WINDOW_SECONDS = 60;

    private final Map<Long, Deque<Long>> keyRequestTimestamps = new ConcurrentHashMap<>();

    @Getter
    @AllArgsConstructor
    public static class RateLimitResult {
        private final boolean allowed;
        private final int limit;
        private final int remaining;
        private final long resetSeconds;
    }

    public synchronized RateLimitResult checkAndConsume(Long apiKeyId, int limitPerMinute) {
        if (limitPerMinute <= 0) {
            return new RateLimitResult(true, limitPerMinute, limitPerMinute, 0);
        }

        long now = Instant.now().getEpochSecond();
        long windowStart = now - WINDOW_SECONDS;

        Deque<Long> timestamps = keyRequestTimestamps.computeIfAbsent(apiKeyId, k -> new ArrayDeque<>());

        // Evict expired timestamps
        while (!timestamps.isEmpty() && timestamps.peekFirst() <= windowStart) {
            timestamps.pollFirst();
        }

        int currentCount = timestamps.size();
        long oldestTimestamp = timestamps.isEmpty() ? now : timestamps.peekFirst();
        long resetSeconds = Math.max(1, (oldestTimestamp + WINDOW_SECONDS) - now);

        if (currentCount >= limitPerMinute) {
            return new RateLimitResult(false, limitPerMinute, 0, resetSeconds);
        }

        timestamps.addLast(now);
        int remaining = Math.max(0, limitPerMinute - (currentCount + 1));
        return new RateLimitResult(true, limitPerMinute, remaining, resetSeconds);
    }

    public void clear(Long apiKeyId) {
        keyRequestTimestamps.remove(apiKeyId);
    }
}
