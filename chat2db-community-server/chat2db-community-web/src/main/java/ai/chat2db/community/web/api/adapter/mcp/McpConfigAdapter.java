package ai.chat2db.community.web.api.adapter.mcp;

import ai.chat2db.community.domain.api.service.mcp.IMcpConfigService;
import ai.chat2db.community.tools.http.LocalCookie;
import ai.chat2db.community.tools.util.ConfigUtils;
import ai.chat2db.community.tools.util.SystemSettingsUtil;
import ai.chat2db.community.web.api.config.mcp.security.McpSecurityConstants;
import ai.chat2db.community.web.api.model.http.CookieUtil;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Builds web MCP configuration from runtime web context.
 */
@Component
@Slf4j
public class McpConfigAdapter implements IMcpConfigService {

    private final Environment environment;

    private final ObjectProvider<ServletWebServerApplicationContext> webServerApplicationContextProvider;

    public McpConfigAdapter(Environment environment,
                            ObjectProvider<ServletWebServerApplicationContext> webServerApplicationContextProvider) {
        this.environment = environment;
        this.webServerApplicationContextProvider = webServerApplicationContextProvider;
    }

    @Override
    public String copyConfig() {
        String baseUrl = resolveBaseUrl();
        String mcpUrl = baseUrl + "/mcp";
        Map<String, String> headers = buildHeaders();
        String serverName = "chat2db";

        JSONObject server = new JSONObject();
        server.put("type", "streamable-http");
        server.put("url", mcpUrl);
        if (!headers.isEmpty()) {
            server.put("headers", headers);
        }

        JSONObject mcpServers = new JSONObject();
        mcpServers.put(serverName, server);

        JSONObject root = new JSONObject();
        root.put("mcpServers", mcpServers);
        log.info("Generated MCP config serverName={}, type=streamable-http, url={}, clientMode={}, desktop={}, gui={}, headers={}",
                serverName,
                mcpUrl,
                isDesktopGuiClient() ? "desktop-gui" : "web",
                ConfigUtils.isDesktop(),
                ConfigUtils.isShowGUI(),
                headers.keySet());
        return root.toJSONString(JSONWriter.Feature.PrettyFormat);
    }

    private String resolveBaseUrl() {
        if (!isDesktopGuiClient()) {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null && attributes.getRequest() != null) {
                String requestBaseUrl = resolveRequestBaseUrl(attributes.getRequest());
                if (StringUtils.isNotBlank(requestBaseUrl)) {
                    return requestBaseUrl;
                }
            }
        }
        String scheme = environment != null && environment.getProperty("server.ssl.enabled", Boolean.class, false)
                ? "https"
                : "http";
        String rawAddress = environment == null ? null : environment.getProperty("server.address");
        String host = normalizeBindAddress(rawAddress);
        return scheme + "://" + host + ":" + resolveServerPort();
    }

    static String resolveRequestBaseUrl(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String scheme = resolveRequestScheme(request);
        String forwardedHost = firstHeaderToken(request.getHeader("X-Forwarded-Host"));
        if (StringUtils.isNotBlank(forwardedHost)) {
            return scheme + "://" + stripDefaultPort(scheme, forwardedHost);
        }
        String hostHeader = firstHeaderToken(request.getHeader(HttpHeaders.HOST));
        if (StringUtils.isNotBlank(hostHeader)) {
            return scheme + "://" + stripDefaultPort(scheme, hostHeader);
        }
        String serverName = request.getServerName();
        if (StringUtils.isBlank(serverName)) {
            return null;
        }
        int serverPort = request.getServerPort();
        String authority = serverPort > 0 ? serverName + ":" + serverPort : serverName;
        return scheme + "://" + stripDefaultPort(scheme, authority);
    }

    private static String resolveRequestScheme(HttpServletRequest request) {
        String forwardedProto = firstHeaderToken(request.getHeader("X-Forwarded-Proto"));
        if ("https".equalsIgnoreCase(forwardedProto) || "http".equalsIgnoreCase(forwardedProto)) {
            return forwardedProto.toLowerCase();
        }
        String cfVisitor = request.getHeader("CF-Visitor");
        if (StringUtils.containsIgnoreCase(cfVisitor, "\"https\"")) {
            return "https";
        }
        if (request.isSecure() || "https".equalsIgnoreCase(request.getScheme())) {
            return "https";
        }
        return "http";
    }

    private static String stripDefaultPort(String scheme, String authority) {
        if ("https".equalsIgnoreCase(scheme) && authority.endsWith(":443")) {
            return authority.substring(0, authority.length() - 4);
        }
        if ("http".equalsIgnoreCase(scheme) && authority.endsWith(":80")) {
            return authority.substring(0, authority.length() - 3);
        }
        return authority;
    }

    private static String firstHeaderToken(String headerValue) {
        if (StringUtils.isBlank(headerValue)) {
            return null;
        }
        String first = headerValue.split(",")[0].trim();
        return first.isEmpty() ? null : first;
    }

    private static String normalizeBindAddress(String address) {
        if (StringUtils.isBlank(address)) {
            return "127.0.0.1";
        }
        String trimmed = address.trim();
        if ("0.0.0.0".equals(trimmed) || "::".equals(trimmed) || "[::]".equals(trimmed) || "0:0:0:0:0:0:0:0".equals(trimmed)) {
            return "127.0.0.1";
        }
        return trimmed;
    }

    private Map<String, String> buildHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        if (isDesktopGuiClient()) {
            headers.put(McpSecurityConstants.MCP_AUTH_HEADER, SystemSettingsUtil.getOrCreateMcpAuthToken());
        }
        if (!isDesktopGuiClient()) {
            String cookieHeader = buildCookieHeader();
            if (cookieHeader != null && !cookieHeader.isBlank()) {
                headers.put("Cookie", cookieHeader);
            }
            String authorization = resolveAuthorizationHeader();
            if (authorization != null && !authorization.isBlank()) {
                headers.put(CookieUtil.AUTHORIZATION, authorization);
            }
        }
        return headers;
    }

    private String buildCookieHeader() {
        if (ConfigUtils.isDesktop()) {
            Map<String, String> cookieMap = new LinkedHashMap<>();
            putIfPresent(cookieMap, CookieUtil.CHAT2DB_USER_ID, LocalCookie.getCookie(CookieUtil.CHAT2DB_USER_ID));
            putIfPresent(cookieMap, CookieUtil.CHAT2DB_ORGANIZATION_TOKEN, LocalCookie.getCookie(CookieUtil.CHAT2DB_ORGANIZATION_TOKEN));
            putIfPresent(cookieMap, CookieUtil.CHAT2DB_ORGANIZATION_ID, LocalCookie.getCookie(CookieUtil.CHAT2DB_ORGANIZATION_ID));
            return cookieMap.entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("; "));
        }
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return null;
        }
        Cookie[] cookies = attributes.getRequest().getCookies();
        if (cookies == null || cookies.length == 0) {
            return null;
        }
        Map<String, String> cookieMap = new LinkedHashMap<>();
        for (Cookie cookie : cookies) {
            if (cookie == null) {
                continue;
            }
            String name = cookie.getName();
            if (CookieUtil.CHAT2DB_USER_ID.equals(name)
                    || CookieUtil.CHAT2DB_ORGANIZATION_TOKEN.equals(name)
                    || CookieUtil.CHAT2DB_ORGANIZATION_ID.equals(name)) {
                putIfPresent(cookieMap, name, cookie.getValue());
            }
        }
        return cookieMap.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("; "));
    }

    private void putIfPresent(Map<String, String> cookieMap, String key, String value) {
        if (value != null && !value.isBlank()) {
            cookieMap.put(key, value);
        }
    }

    private String resolveAuthorizationHeader() {
        if (ConfigUtils.isDesktop()) {
            return LocalCookie.getHeader(CookieUtil.AUTHORIZATION);
        }
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return null;
        }
        return attributes.getRequest().getHeader(CookieUtil.AUTHORIZATION);
    }

    private int resolveServerPort() {
        ServletWebServerApplicationContext webServerApplicationContext =
                webServerApplicationContextProvider.getIfAvailable();
        if (webServerApplicationContext != null && webServerApplicationContext.getWebServer() != null) {
            return webServerApplicationContext.getWebServer().getPort();
        }
        Integer port = environment.getProperty("local.server.port", Integer.class);
        if (port != null) {
            return port;
        }
        return environment.getProperty("server.port", Integer.class, 8080);
    }

    private boolean isDesktopGuiClient() {
        return ConfigUtils.isDesktop() && ConfigUtils.isShowGUI();
    }
}
