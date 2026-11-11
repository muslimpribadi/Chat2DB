package ai.chat2db.community.web.api.config.web.interceptor;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import ai.chat2db.community.tools.util.ConfigUtils;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;


@Component
public class CorsFilter implements Filter {

    public static final String ALLOWED_ORIGINS_PROPERTY = "chat2db.cors.allowed-origins";
    public static final String ALLOWED_ORIGINS_ENV = "CHAT2DB_CORS_ALLOWED_ORIGINS";
    public static final String ALLOW_CLOUDFLARE_TUNNEL_PROPERTY = "chat2db.cors.allow-cloudflare-tunnel";
    public static final String ALLOW_CLOUDFLARE_TUNNEL_ENV = "CHAT2DB_CORS_ALLOW_CLOUDFLARE_TUNNEL";

    private static final Set<String> COMMUNITY_ALLOWED_ORIGINS = Set.of(
            "http://127.0.0.1:8888",
            "http://localhost:8888",
            "http://127.0.0.1:8889",
            "http://localhost:8889",
            "http://127.0.0.1:10825",
            "http://localhost:10825",
            "http://[::1]:10825",
            "http://127.0.0.1:11924",
            "http://localhost:11924",
            "http://[::1]:11924"
    );

    private static final Set<String> LOOPBACK_HOSTS = Set.of(
            "127.0.0.1",
            "localhost",
            "[::1]",
            "::1"
    );

    private static final String DEFAULT_ALLOWED_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD";

    private static final String DEFAULT_ALLOWED_HEADERS = String.join(", ",
            "Content-Type",
            "Accept",
            "Accept-Language",
            "Authorization",
            "DBHUB",
            "uid",
            "Time-Zone",
            "X-Requested-With",
            "Origin",
            "Chat2db-Organization-Id",
            "Chat2db-Organization-Token",
            "Chat2db-BS-TOKEN",
            "CHAT2DB",
            "X-Chat2DB-MCP-Token",
            "X-Chat2DB-DataSource-Id",
            "X-Chat2DB-Trace-Id",
            "Cf-Access-Jwt-Assertion",
            "Cf-Access-Client-Id",
            "Cf-Access-Client-Secret",
            "Cache-Control",
            "Pragma"
    );

    private static final String DEFAULT_EXPOSED_HEADERS = "Chat2db, Content-Disposition, X-Chat2DB-Trace-Id";

    private final Environment environment;
    private final boolean devProfileActive;

    public CorsFilter(Environment environment) {
        this.environment = environment;
        this.devProfileActive = environment != null && environment.matchesProfiles("dev");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
        throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
        HttpServletRequest request = (HttpServletRequest) req;
        String origin = request.getHeader(HttpHeaders.ORIGIN);

        if (ConfigUtils.isCommunity() && !isOriginAllowed(request, origin)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        setCorsHeaders(request, response, origin);
        if (isPreflightRequest(request, origin)) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }
        chain.doFilter(req, res);
    }

    boolean isOriginAllowed(HttpServletRequest request, String origin) {
        return allowCommunityOrigin(
                origin,
                devProfileActive,
                request,
                resolveConfiguredAllowedOrigins(),
                resolveConfiguredPorts(),
                resolveAllowCloudflareTunnel()
        );
    }

    static boolean allowCommunityOrigin(String origin, boolean devProfileActive) {
        return allowCommunityOrigin(
                origin,
                devProfileActive,
                null,
                parseAllowedOrigins(firstNonBlank(
                        System.getProperty(ALLOWED_ORIGINS_PROPERTY),
                        System.getenv(ALLOWED_ORIGINS_ENV)
                )),
                Collections.emptySet(),
                true
        );
    }

    static boolean allowCommunityOrigin(String origin,
                                        boolean devProfileActive,
                                        HttpServletRequest request,
                                        Set<String> configuredOrigins,
                                        Set<Integer> configuredPorts,
                                        boolean allowCloudflareTunnel) {
        if (devProfileActive || origin == null || origin.isBlank()) {
            return true;
        }
        String normalizedOrigin = trimTrailingSlash(origin.trim());
        if (COMMUNITY_ALLOWED_ORIGINS.contains(normalizedOrigin.toLowerCase(Locale.ROOT))) {
            return true;
        }

        URI originUri = parseHttpOriginUri(normalizedOrigin);
        if (originUri == null) {
            return false;
        }

        String originHost = normalizeHost(originUri.getHost());
        int originPort = effectivePort(originUri.getScheme(), originUri.getPort());

        if (isLoopbackHost(originHost) && configuredPorts != null && configuredPorts.contains(originPort)) {
            return true;
        }

        if (matchesConfiguredOrigins(normalizedOrigin, originUri, originHost, configuredOrigins)) {
            return true;
        }

        if (request != null && matchesRequestOrigin(originUri, originHost, originPort, request)) {
            return true;
        }

        if (allowCloudflareTunnel && isCloudflareTunnelOriginAllowed(originUri, originHost, request)) {
            return true;
        }

        return false;
    }

    private Set<String> resolveConfiguredAllowedOrigins() {
        String raw = null;
        if (environment != null) {
            raw = firstNonBlank(
                    environment.getProperty(ALLOWED_ORIGINS_PROPERTY),
                    environment.getProperty(ALLOWED_ORIGINS_ENV)
            );
        }
        if (StringUtils.isBlank(raw)) {
            raw = firstNonBlank(
                    System.getProperty(ALLOWED_ORIGINS_PROPERTY),
                    System.getenv(ALLOWED_ORIGINS_ENV)
            );
        }
        return parseAllowedOrigins(raw);
    }

    private Set<Integer> resolveConfiguredPorts() {
        Set<Integer> ports = new LinkedHashSet<>();
        addPortIfValid(ports, getProperty("server.port"));
        addPortIfValid(ports, getProperty("local.server.port"));
        addPortIfValid(ports, getProperty("CHAT2DB_PORT"));
        addPortIfValid(ports, getProperty("CHAT2DB_SERVER_PORT"));
        addPortIfValid(ports, System.getenv("CHAT2DB_PORT"));
        addPortIfValid(ports, System.getenv("CHAT2DB_SERVER_PORT"));
        addPortIfValid(ports, System.getenv("SERVER_PORT"));
        return ports;
    }

    private boolean resolveAllowCloudflareTunnel() {
        String raw = firstNonBlank(
                getProperty(ALLOW_CLOUDFLARE_TUNNEL_PROPERTY),
                getProperty(ALLOW_CLOUDFLARE_TUNNEL_ENV),
                System.getProperty(ALLOW_CLOUDFLARE_TUNNEL_PROPERTY),
                System.getenv(ALLOW_CLOUDFLARE_TUNNEL_ENV)
        );
        if (StringUtils.isBlank(raw)) {
            return true;
        }
        return Boolean.parseBoolean(raw.trim());
    }

    private String getProperty(String key) {
        return environment == null ? null : environment.getProperty(key);
    }

    static Set<String> parseAllowedOrigins(String raw) {
        if (StringUtils.isBlank(raw)) {
            return Collections.emptySet();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .map(CorsFilter::trimTrailingSlash)
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static boolean matchesConfiguredOrigins(String normalizedOrigin,
                                                    URI originUri,
                                                    String originHost,
                                                    Set<String> configuredOrigins) {
        if (configuredOrigins == null || configuredOrigins.isEmpty()) {
            return false;
        }
        String lowerOrigin = normalizedOrigin.toLowerCase(Locale.ROOT);
        String originScheme = originUri.getScheme().toLowerCase(Locale.ROOT);
        int originPort = originUri.getPort();

        for (String pattern : configuredOrigins) {
            if (StringUtils.isBlank(pattern)) {
                continue;
            }
            String lowerPattern = trimTrailingSlash(pattern.trim()).toLowerCase(Locale.ROOT);
            if ("*".equals(lowerPattern)) {
                return true;
            }
            if (lowerOrigin.equals(lowerPattern)) {
                return true;
            }
            if (matchesOriginPattern(originScheme, originHost, originPort, lowerPattern)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesOriginPattern(String originScheme,
                                                String originHost,
                                                int originPort,
                                                String lowerPattern) {
        String patternBody = lowerPattern;
        if (patternBody.startsWith("http://") || patternBody.startsWith("https://")) {
            int schemeEnd = patternBody.indexOf("://");
            String patternScheme = patternBody.substring(0, schemeEnd);
            if (!patternScheme.equals(originScheme)) {
                return false;
            }
            patternBody = patternBody.substring(schemeEnd + 3);
        }

        String patternHost = patternBody;
        String patternPort = null;
        int colonIndex = findPortSeparator(patternBody);
        if (colonIndex >= 0) {
            patternHost = patternBody.substring(0, colonIndex);
            patternPort = patternBody.substring(colonIndex + 1);
        }

        if (!matchesHostPattern(originHost, normalizeHost(patternHost))) {
            return false;
        }

        if (patternPort == null) {
            return true;
        }
        if ("*".equals(patternPort)) {
            return true;
        }
        try {
            int expectedPort = Integer.parseInt(patternPort);
            int effectiveOriginPort = effectivePort(originScheme, originPort);
            return effectiveOriginPort == expectedPort;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean matchesHostPattern(String host, String patternHost) {
        if (StringUtils.isBlank(host) || StringUtils.isBlank(patternHost)) {
            return false;
        }
        if ("*".equals(patternHost) || host.equals(patternHost)) {
            return true;
        }
        if (patternHost.startsWith("*.")) {
            String suffix = patternHost.substring(1); // ".example.com"
            String rootDomain = patternHost.substring(2); // "example.com"
            return host.equals(rootDomain) || (host.endsWith(suffix) && host.length() > suffix.length());
        }
        return false;
    }

    private static boolean matchesRequestOrigin(URI originUri,
                                                String originHost,
                                                int originPort,
                                                HttpServletRequest request) {
        Set<String> candidateAuthorities = extractRequestAuthorities(request);
        int serverPort = request.getServerPort();
        int localPort = request.getLocalPort();
        boolean loopbackOrigin = isLoopbackHost(originHost);

        for (String authority : candidateAuthorities) {
            if (StringUtils.isBlank(authority)) {
                continue;
            }
            String trimmed = authority.trim();
            String candidateHost = trimmed;
            Integer candidatePort = null;
            int colonIndex = findPortSeparator(trimmed);
            if (colonIndex >= 0) {
                candidateHost = trimmed.substring(0, colonIndex);
                String portStr = trimmed.substring(colonIndex + 1);
                try {
                    candidatePort = Integer.parseInt(portStr);
                } catch (NumberFormatException ignored) {
                    continue;
                }
            }
            candidateHost = normalizeHost(candidateHost);
            if (!originHost.equals(candidateHost)) {
                continue;
            }

            if (loopbackOrigin) {
                // For loopback origins, require an explicit port match against the candidate authority or server port
                // so unrelated local apps on other ports cannot make cross-origin calls without configuration.
                if (candidatePort != null && candidatePort == originPort) {
                    return true;
                }
                if (candidatePort == null && (originPort == serverPort || originPort == localPort)) {
                    return true;
                }
                continue;
            }

            // For non-loopback domains (e.g., Cloudflare Tunnel or reverse proxy with a domain name):
            // If the Origin host matches the request's Host / X-Forwarded-Host / Forwarded host, allow it
            // when ports match, when the proxy stripped/omitted the port, or when the proxy forwarded to the local port.
            if (candidatePort == null
                    || candidatePort == originPort
                    || candidatePort == serverPort
                    || candidatePort == localPort
                    || candidatePort == 10825
                    || candidatePort == 80
                    || candidatePort == 443) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> extractRequestAuthorities(HttpServletRequest request) {
        Set<String> authorities = new LinkedHashSet<>();

        addCommaSeparatedHeaderValues(authorities, request.getHeader("X-Forwarded-Host"));
        addForwardedHeaderHosts(authorities, request.getHeader("Forwarded"));
        addCommaSeparatedHeaderValues(authorities, request.getHeader(HttpHeaders.HOST));

        String serverName = request.getServerName();
        if (StringUtils.isNotBlank(serverName)) {
            int serverPort = request.getServerPort();
            if (serverPort > 0) {
                String formattedHost = serverName.contains(":") && !serverName.startsWith("[")
                        ? "[" + serverName + "]"
                        : serverName;
                authorities.add(formattedHost + ":" + serverPort);
            }
            if (!isLoopbackHost(normalizeHost(serverName))) {
                authorities.add(serverName);
            }
        }
        return authorities;
    }

    private static void addCommaSeparatedHeaderValues(Set<String> target, String headerValue) {
        if (StringUtils.isBlank(headerValue)) {
            return;
        }
        for (String part : headerValue.split(",")) {
            String trimmed = part.trim();
            if (StringUtils.isNotBlank(trimmed)) {
                target.add(trimmed);
            }
        }
    }

    private static void addForwardedHeaderHosts(Set<String> target, String forwardedHeader) {
        if (StringUtils.isBlank(forwardedHeader)) {
            return;
        }
        for (String element : forwardedHeader.split(",")) {
            for (String param : element.split(";")) {
                String trimmed = param.trim();
                if (trimmed.regionMatches(true, 0, "host=", 0, 5)) {
                    String value = trimmed.substring(5).trim();
                    if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                        value = value.substring(1, value.length() - 1);
                    }
                    if (StringUtils.isNotBlank(value)) {
                        target.add(value);
                    }
                }
            }
        }
    }

    private static boolean isCloudflareTunnelOriginAllowed(URI originUri,
                                                           String originHost,
                                                           HttpServletRequest request) {
        if (isLoopbackHost(originHost)) {
            return false;
        }
        if (originHost.endsWith(".trycloudflare.com") || originHost.endsWith(".cfargotunnel.com")) {
            return true;
        }
        if (request == null) {
            return false;
        }
        String cfRay = request.getHeader("CF-Ray");
        if (StringUtils.isBlank(cfRay)) {
            return false;
        }
        boolean hasCloudflareContext = StringUtils.isNotBlank(request.getHeader("CF-Connecting-IP"))
                || StringUtils.isNotBlank(request.getHeader("CF-Visitor"))
                || StringUtils.containsIgnoreCase(request.getHeader("CDN-Loop"), "cloudflare")
                || StringUtils.isNotBlank(request.getHeader("Cf-Access-Jwt-Assertion"))
                || StringUtils.isNotBlank(request.getHeader("Cf-Warp-Tag-Id"));
        if (!hasCloudflareContext) {
            return false;
        }
        String scheme = originUri.getScheme();
        return "https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme);
    }

    private static URI parseHttpOriginUri(String origin) {
        try {
            URI uri = URI.create(origin);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return null;
            }
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return null;
            }
            return uri;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isLoopbackHost(String host) {
        if (StringUtils.isBlank(host)) {
            return false;
        }
        return LOOPBACK_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }

    private static String normalizeHost(String host) {
        if (StringUtils.isBlank(host)) {
            return "";
        }
        String lower = host.trim().toLowerCase(Locale.ROOT);
        if (lower.startsWith("[") && lower.endsWith("]") && lower.length() > 2) {
            return lower.substring(1, lower.length() - 1);
        }
        return lower;
    }

    private static int effectivePort(String scheme, int port) {
        if (port > 0) {
            return port;
        }
        return "https".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private static int findPortSeparator(String authority) {
        if (StringUtils.isBlank(authority)) {
            return -1;
        }
        if (authority.startsWith("[")) {
            int closeBracket = authority.indexOf(']');
            if (closeBracket >= 0 && closeBracket + 1 < authority.length() && authority.charAt(closeBracket + 1) == ':') {
                return closeBracket + 1;
            }
            return -1;
        }
        int firstColon = authority.indexOf(':');
        int lastColon = authority.lastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon) {
            return firstColon;
        }
        return -1;
    }

    private static void addPortIfValid(Set<Integer> ports, String rawPort) {
        if (StringUtils.isBlank(rawPort)) {
            return;
        }
        try {
            int port = Integer.parseInt(rawPort.trim());
            if (port > 0 && port <= 65535) {
                ports.add(port);
            }
        } catch (NumberFormatException ignored) {
        }
    }

    private static String trimTrailingSlash(String value) {
        if (value == null) {
            return null;
        }
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') {
            end--;
        }
        return value.substring(0, end);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.isNotBlank(value)) {
                return value;
            }
        }
        return null;
    }

    private static boolean isPreflightRequest(HttpServletRequest request, String origin) {
        return request != null
                && StringUtils.isNotBlank(origin)
                && "OPTIONS".equalsIgnoreCase(request.getMethod())
                && StringUtils.isNotBlank(request.getHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD));
    }

    private static void setCorsHeaders(HttpServletRequest request, HttpServletResponse response, String origin) {
        if (StringUtils.isNotBlank(origin)) {
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
        }
        response.setHeader(HttpHeaders.VARY, "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
        response.setHeader("Access-Control-Allow-Methods", DEFAULT_ALLOWED_METHODS);
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", resolveAllowedHeaders(request));
        response.setHeader("Access-Control-Expose-Headers", DEFAULT_EXPOSED_HEADERS);
    }

    private static String resolveAllowedHeaders(HttpServletRequest request) {
        if (request == null) {
            return DEFAULT_ALLOWED_HEADERS;
        }
        String requestedHeaders = request.getHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (StringUtils.isBlank(requestedHeaders)) {
            return DEFAULT_ALLOWED_HEADERS;
        }
        Set<String> merged = new LinkedHashSet<>();
        for (String header : DEFAULT_ALLOWED_HEADERS.split(",")) {
            merged.add(header.trim());
        }
        for (String header : requestedHeaders.split(",")) {
            String trimmed = header.trim();
            if (isValidHeaderToken(trimmed) && merged.stream().noneMatch(existing -> existing.equalsIgnoreCase(trimmed))) {
                merged.add(trimmed);
            }
        }
        return String.join(", ", merged);
    }

    private static boolean isValidHeaderToken(String token) {
        if (StringUtils.isBlank(token) || token.length() > 128) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean alphaNum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            boolean allowedSymbol = c == '-' || c == '_';
            if (!alphaNum && !allowedSymbol) {
                return false;
            }
        }
        return true;
    }

}
