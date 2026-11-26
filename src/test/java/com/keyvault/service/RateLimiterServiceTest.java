package com.keyvault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RateLimiterServiceTest {

    private RateLimiterService rateLimiterService;

    @BeforeEach
    void setUp() {
        rateLimiterService = new RateLimiterService();
    }

    @Test
    void testUnderLimitAllowed() {
        RateLimiterService.RateLimitResult res1 = rateLimiterService.checkAndConsume(1L, 2);
        assertTrue(res1.isAllowed());
        assertEquals(2, res1.getLimit());
        assertEquals(1, res1.getRemaining());

        RateLimiterService.RateLimitResult res2 = rateLimiterService.checkAndConsume(1L, 2);
        assertTrue(res2.isAllowed());
        assertEquals(0, res2.getRemaining());
    }

    @Test
    void testExceedingLimitRejects() {
        rateLimiterService.checkAndConsume(2L, 2);
        rateLimiterService.checkAndConsume(2L, 2);

        RateLimiterService.RateLimitResult res3 = rateLimiterService.checkAndConsume(2L, 2);
        assertFalse(res3.isAllowed());
        assertEquals(0, res3.getRemaining());
        assertTrue(res3.getResetSeconds() >= 1);
    }

    @Test
    void testClearKeyResetsLimit() {
        rateLimiterService.checkAndConsume(3L, 1);
        assertFalse(rateLimiterService.checkAndConsume(3L, 1).isAllowed());

        rateLimiterService.clear(3L);
        assertTrue(rateLimiterService.checkAndConsume(3L, 1).isAllowed());
    }

    @Test
    void testEvictsStaleBucketsAfterWindowExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-11-26T10:00:00Z"));
        RateLimiterService timedLimiter = new RateLimiterService(clock);

        timedLimiter.checkAndConsume(10L, 5);
        timedLimiter.checkAndConsume(11L, 5);
        assertEquals(2, timedLimiter.getTrackedKeyCount());

        // Advance 30 seconds: buckets are still active
        clock.advance(Duration.ofSeconds(30));
        assertEquals(0, timedLimiter.evictStaleEntries());
        assertEquals(2, timedLimiter.getTrackedKeyCount());

        // Advance another 31 seconds (total 61s > 60s window): idle buckets are evicted
        clock.advance(Duration.ofSeconds(31));
        assertEquals(2, timedLimiter.evictStaleEntries());
        assertEquals(0, timedLimiter.getTrackedKeyCount());
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant initial) {
            this.instant = initial;
        }

        void advance(Duration duration) {
            this.instant = this.instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
