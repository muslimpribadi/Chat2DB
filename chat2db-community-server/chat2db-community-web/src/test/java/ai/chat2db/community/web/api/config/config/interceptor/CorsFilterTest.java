package ai.chat2db.community.web.api.config.web.interceptor;

import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorsFilterTest {

    @Test
    void releaseAllowsOnlyKnownFrontendOriginsOrMissingOrigin() {
        assertTrue(CorsFilter.allowCommunityOrigin(null, false));
        assertTrue(CorsFilter.allowCommunityOrigin("", false));
        assertTrue(CorsFilter.allowCommunityOrigin("http://127.0.0.1:8888", false));
        assertTrue(CorsFilter.allowCommunityOrigin("http://127.0.0.1:8889", false));
        assertTrue(CorsFilter.allowCommunityOrigin("http://localhost:8889", false));
        assertTrue(CorsFilter.allowCommunityOrigin("http://localhost:10825", false));
        assertTrue(CorsFilter.allowCommunityOrigin("http://[::1]:10825", false));

        assertFalse(CorsFilter.allowCommunityOrigin("https://example.com", false));
        assertFalse(CorsFilter.allowCommunityOrigin("http://127.0.0.1:3000", false));
    }

    @Test
    void developmentAllowsAllOrigins() {
        assertTrue(CorsFilter.allowCommunityOrigin("https://example.com", true));
        assertTrue(CorsFilter.allowCommunityOrigin("http://127.0.0.1:3000", true));
    }

    @Test
    void releaseAllowsSameOriginDomainOverCloudflareTunnelAndReverseProxy() {
        MockHttpServletRequest cfRequest = new MockHttpServletRequest("POST", "/api/rdb/ddl/execute");
        cfRequest.setServerName("db.example.com");
        cfRequest.setServerPort(10825);
        cfRequest.addHeader(HttpHeaders.HOST, "db.example.com");
        cfRequest.addHeader("X-Forwarded-Proto", "https");
        cfRequest.addHeader("X-Forwarded-Host", "db.example.com");

        assertTrue(CorsFilter.allowCommunityOrigin(
                "https://db.example.com",
                false,
                cfRequest,
                Collections.emptySet(),
                Set.of(10825),
                true
        ));

        // Cross-origin request from an unrelated external site must still be rejected
        assertFalse(CorsFilter.allowCommunityOrigin(
                "https://malicious.example.org",
                false,
                cfRequest,
                Collections.emptySet(),
                Set.of(10825),
                false
        ));
    }

    @Test
    void releaseAllowsCloudflareTunnelWhenHostHeaderIsRewrittenToLocalhost() {
        MockHttpServletRequest tunnelRequest = new MockHttpServletRequest("POST", "/api/connection/datasource/create");
        tunnelRequest.setServerName("127.0.0.1");
        tunnelRequest.setServerPort(10825);
        tunnelRequest.addHeader(HttpHeaders.HOST, "127.0.0.1:10825");
        tunnelRequest.addHeader("CF-Ray", "89abcdef01234567-SIN");
        tunnelRequest.addHeader("CF-Connecting-IP", "203.0.113.10");
        tunnelRequest.addHeader("CF-Visitor", "{\"scheme\":\"https\"}");

        assertTrue(CorsFilter.allowCommunityOrigin(
                "https://chat2db.mydomain.com",
                false,
                tunnelRequest,
                Collections.emptySet(),
                Set.of(10825),
                true
        ));

        // Quick tunnel domains (*.trycloudflare.com) are also allowed when allowCloudflareTunnel is enabled
        assertTrue(CorsFilter.allowCommunityOrigin(
                "https://random-words-tunnel.trycloudflare.com",
                false,
                null,
                Collections.emptySet(),
                Set.of(10825),
                true
        ));
    }

    @Test
    void releaseAllowsCustomConfiguredServerPortsAndConfiguredOriginPatterns() {
        assertTrue(CorsFilter.allowCommunityOrigin(
                "http://127.0.0.1:18025",
                false,
                null,
                Collections.emptySet(),
                Set.of(18025),
                true
        ));
        assertTrue(CorsFilter.allowCommunityOrigin(
                "http://localhost:18025",
                false,
                null,
                Collections.emptySet(),
                Set.of(18025),
                true
        ));

        Set<String> configuredOrigins = CorsFilter.parseAllowedOrigins(
                "https://*.internal.example.com, https://db.company.io:8443, http://localhost:*"
        );
        assertTrue(CorsFilter.allowCommunityOrigin(
                "https://sql.internal.example.com",
                false,
                null,
                configuredOrigins,
                Collections.emptySet(),
                false
        ));
        assertTrue(CorsFilter.allowCommunityOrigin(
                "https://db.company.io:8443",
                false,
                null,
                configuredOrigins,
                Collections.emptySet(),
                false
        ));
        assertTrue(CorsFilter.allowCommunityOrigin(
                "http://localhost:3000",
                false,
                null,
                configuredOrigins,
                Collections.emptySet(),
                false
        ));
    }

    @Test
    void preflightOptionsRequestReturnsOkWithMergedAllowedHeaders() throws Exception {
        MockEnvironment env = new MockEnvironment()
                .withProperty("spring.profiles.active", "release")
                .withProperty(CorsFilter.ALLOWED_ORIGINS_PROPERTY, "https://db.example.com");
        CorsFilter filter = new CorsFilter(env);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/api/system");
        request.addHeader(HttpHeaders.ORIGIN, "https://db.example.com");
        request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST");
        request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type, X-Custom-Tunnel-Header");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertEquals("https://db.example.com", response.getHeader("Access-Control-Allow-Origin"));
        assertEquals("true", response.getHeader("Access-Control-Allow-Credentials"));
        assertTrue(response.getHeader("Access-Control-Allow-Headers").contains("X-Custom-Tunnel-Header"));
        assertNull(chain.getRequest());
    }
}
