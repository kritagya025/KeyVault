package com.keyvault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    }

    @Test
    void testClearKeyResetsLimit() {
        rateLimiterService.checkAndConsume(3L, 1);
        assertFalse(rateLimiterService.checkAndConsume(3L, 1).isAllowed());

        rateLimiterService.clear(3L);
        assertTrue(rateLimiterService.checkAndConsume(3L, 1).isAllowed());
    }
}
