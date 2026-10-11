package com.keyvault.util;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IpUtilsTest {

    @Test
    void testGetClientIpDirect() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.50");
        assertEquals("192.168.1.50", IpUtils.getClientIp(request));
    }

    @Test
    void testGetClientIpXForwardedFor() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178");
        assertEquals("203.0.113.195", IpUtils.getClientIp(request));
    }

    @Test
    void testExactMatchIPv4() {
        assertTrue(IpUtils.matches("192.168.1.100", "192.168.1.100"));
        assertFalse(IpUtils.matches("192.168.1.101", "192.168.1.100"));
    }

    @Test
    void testLoopbackIPv6AndIPv4() {
        assertTrue(IpUtils.matches("127.0.0.1", "127.0.0.1"));
        assertTrue(IpUtils.matches("::1", "127.0.0.1"));
        assertTrue(IpUtils.matches("0:0:0:0:0:0:0:1", "127.0.0.1"));
    }

    @Test
    void testCidrRangeMatch() {
        assertTrue(IpUtils.matches("192.168.1.55", "192.168.1.0/24"));
        assertFalse(IpUtils.matches("192.168.2.1", "192.168.1.0/24"));
        assertTrue(IpUtils.matches("10.5.20.1", "10.0.0.0/8"));
    }
}
