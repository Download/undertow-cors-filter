package com.stijndewitt.undertow.cors;

import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;

/**
 * Undertow filter to add CORS headers based on a policy.
 * 
 * <p>This class implements {@code HttpHandler} to intercept all requests and add cors headers.</p>
 * 
 * <p>There seems to be an oversight in Java EE's filter handling, because when a user that is not 
 * (yet) authenticated attempts to access a protected resource, the container intercepts that request 
 * and sends a 401 response. That response does not have CORS headers, but for some reason cannot be 
 * filtered. Neither with a Jax-Rs ContainerResponseFilter, not with a plain servlet filter. An 
 * undertow filter seems to be the only way to get the job done.</p>
 * 
 * <p>To use this filter, install it as a module in WildFly or EAP or whatever JBoss calls their 
 * container nowadays. Put the JAR {@code undertow-cors-filter-X.Y.Z.jar} (where X.Y.Z is 
 * the version number) in a folder {@code modules/com/stijndewitt/undertow/cors/main} in the root
 * of the server. Then add a module.xml with this content:</p>
 * 
 * <pre><code>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;module xmlns="urn:jboss:module:1.0" name="com.stijndewitt.undertow.cors"&gt;
  &lt;resources&gt;
    &lt;resource-root path="undertow-cors-filter-1.0.0.jar"/&gt;
  &lt;/resources&gt;
  &lt;dependencies&gt;
    &lt;module name="io.undertow.core"/&gt;
  &lt;/dependencies&gt;
&lt;/module&gt;</code></pre>
 *
 * <p>Next, add a filter to the {@code filters} section of {@code standalone.xml}:</p>
 * 
 * <pre><code>
...
&lt;filters&gt;
  &lt;filter name="cors-filter" class-name="com.stijndewitt.undertow.cors.Filter" module="com.stijndewitt.undertow.cors"&gt;
    &lt;param name="urlPattern" value="^/api/.*"&gt;

    &lt;param name="policyClass" value="com.stijndewitt.undertow.cors.AllowAll" /&gt;

    &lt;!-- param name="policyClass" value="com.stijndewitt.undertow.cors.AllowMatching" / --&gt;
    &lt;!-- param name="policyParam" value="^http(s)?://(www\.)?example\.(com|org)$" / --&gt;
	
    &lt;!-- param name="policyClass" value="com.stijndewitt.undertow.cors.Whitelist" / --&gt;
    &lt;!-- param name="policyParam" value="${jboss.server.data.dir}/whitelist.txt" / --&gt;
  &lt;/filter&gt;
&lt;/filters&gt;</code></pre>
 * 
 * <p>The commented out stuff illustrates alternatives to the default policy of AllowAll.</p>
 * 
 * <p>Finally, add a {@code filter-ref} to the {@code host} element (still in standalone.xml):</p>
 *
 * <pre><code>
&lt;host name="default-host" alias="localhost"&gt;
	&lt;filter-ref name="cors-filter"/&gt;
&lt;/host&gt;</code></pre>
 *
 * <p>Obviously this filter is container specific. It should work in containers based on Undertow.
 * This includes Wildfly 8/9/10, JBoss AS, JBoss EAP and Wildfly Swarm.</p>
 * 
 * @see Policy
 * @see AllowAll
 * @see AllowMatching
 * @see Whitelist
 */
public class Filter implements HttpHandler {
	private static final Logger LOG = Logger.getLogger(Filter.class.getName());

	/**
	 * The main CORS header indicating if cross-origin access is allowed. 
	 * 
	 * <p>If it's value is equal to the requesting origin, cross-origin access from that origin is allowed.
	 * If it differs, cross-origin access is denied. "*" allows all resources, but is only valid for requests that
	 * do not include credentials (Authorization header, session cookie).</p>
	 * 
	 * <p>This filter simply echoes the origin of the request if the request was allowed by the
	 * selected policy class, because this is valid under all circumstances.</p>
	 * 
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Allow-Origin"
	 * 		>Access-Control-Allow_Origin (MDN)</a>
	 * @see #getPolicyClass
	 * @see #setPolicyClass
	 * @see #DEFAULT_POLICY_CLASS
	 */
	public static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
	
	/**
	 * Indicates whether cross-origin access with credentials (Authorization header, cookies) is allowed.
	 * 
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Allow-Credentials"
	 * 		>Access-Control-Allow-Credentials (MDN)</a>
	 * @see #getAllowCredentials
	 * @see #setAllowCredentials
	 * @see #DEFAULT_ALLOW_CREDENTIALS 
	 */
	public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
	
	/**
	 * Used in response to a preflight request to indicate which HTTP headers can be used 
	 * when making the actual request.
	 * 
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Allow-Headers"
	 * 		>Access-Control-Allow-Headers (MDN)</a>
	 * @see #getAllowHeaders
	 * @see #setAllowHeaders
	 * @see #DEFAULT_ALLOW_HEADERS
	 */
	public static final String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
	
	/**
	 * Used in response to a preflight request to indicate which HTTP methods can be used when making the actual request.
	 * 
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Allow-Methods"
	 * 		>Access-Control-Allow-Methods (MDN)</a>
	 * @see #getAllowMethods
	 * @see #setAllowMethods
	 * @see #DEFAULT_ALLOW_METHODS
	 */
	public static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
	
	/**
	 * Lets a server whitelist headers that browsers are allowed to access.
	 * 
	 * <p>Default headers allowed without needing to be exposed: 
	 * Cache-Control, Content-Language, Content-Type, Expires, Last-Modified, Pragma</p>
	 * 
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Expose-Headers"
	 * 		>Access-Control-Expose-Headers (MDN)</a>
	 * @see #getExposeHeaders
	 * @see #setExposeHeaders
	 * @see #DEFAULT_EXPOSE_HEADERS
	 */
	public static final String ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
	
	/**
	 * The max age header determines how long browsers are allowed to cache the CORS responses.
	 * 
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Access-Control-Max-Age"
	 * 		>Access-Control-Max-Age (MDN)</a>
	 * @see #getMaxAge
	 * @see #setMaxAge
	 * @see #DEFAULT_MAX_AGE
	 */
	public static final String ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
	
	/** 
	 * These headers are considered 'simple' by the spec and as such always exposed.
	 * 
	 * <p>This constant is purely here for documentation purposes. It is not actually used.</p>
	 *  
	 * @see <a href="https://www.w3.org/TR/cors/#simple-response-header"
	 * 		>https://w3.org/TR/cors/#simple-response-header</a>
	 */
	public static final String SIMPLE_RESPONSE_HEADERS = "Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma";

	/**
	 * The default URL pattern that will be used if no {@code urlPattern} parameter was provided in the filter config.
	 * 
	 * @see #getUrlPattern
	 * @see #setUrlPattern
	 */
	public static final String DEFAULT_URL_PATTERN = "^.*$";
	
	/**
	 * The default policy class that will be used if no {@code policyClass} parameter was provided in the filter config.
	 * 
	 * @see #getPolicyClass
	 * @see #setPolicyClass
	 */
	public static final String DEFAULT_POLICY_CLASS = "com.bridalapp.platform.cors.AllowAll";
	
	/**
	 * The default policy parameter that will be used if no {@code policyParam} parameter was provided in the filter config.
	 * 
	 * @see #getPolicyParam
	 * @see #setPolicyParam
	 */
	public static final String DEFAULT_POLICY_PARAM = "";
	
	/**
	 * The default max. age that will be used if no {@code maxAge} parameter was provided in the filter config.
	 *
	 * @see #ACCESS_CONTROL_MAX_AGE
	 * @see #getMaxAge
	 * @see #setMaxAge
	 */
	public static final String DEFAULT_MAX_AGE = "864000"; // 10 days
	
	/**
	 * The default allow credentials that will be used if no {@code allowCredentials} parameter was provided in the filter config.
	 * 
	 * @see #ACCESS_CONTROL_ALLOW_CREDENTIALS
	 * @see #getAllowCredentials
	 * @see #setAllowCredentials
	 */
	public static final String DEFAULT_ALLOW_CREDENTIALS = "true";
	
	/**
	 * The default allow methods that will be used if no {@code allowMethods} parameter was provided in the filter config.
	 * 
	 * @see #ACCESS_CONTROL_ALLOW_METHODS
	 * @see #getAllowMethods
	 * @see #setAllowMethods
	 */
	public static final String DEFAULT_ALLOW_METHODS = "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT";
	
	/**
	 * The default allow headers that will be used if no {@code allowHeaders} parameter was provided in the filter config.
	 * 
	 * @see #ACCESS_CONTROL_ALLOW_HEADERS
	 * @see #getAllowHeaders
	 * @see #setAllowHeaders
	 */
	public static final String DEFAULT_ALLOW_HEADERS = "Authorization,Content-Type,Link,X-Total-Count,Range";

	/**
	 * The default expose headers that will be used if no {@code exposeHeaders} parameter was provided in the filter config.
	 * 
	 * @see #ACCESS_CONTROL_EXPOSE_HEADERS
	 * @see #getExposeHeaders
	 * @see #setExposeHeaders
	 */
	public static final String DEFAULT_EXPOSE_HEADERS = "Accept-Ranges,Content-Length,Content-Range,ETag,Link,Server,X-Total-Count";

	private HttpHandler next;
	// to what URLs does the filter apply?
	private String urlPattern;
	// What policy governs the application of CORS headers?
	private String policyClass;
	private String policyParam;
	// What headers should be set to what values?
	private String exposeHeaders;
	private String maxAge;
	private String allowCredentials;
	private String allowMethods;
	private String allowHeaders;
	
	private transient Policy policy;
	private transient Pattern pattern;

	/**
	 * Constructs the filter.
	 * 
	 * <p>This constructor will be called by Undertow to construct the CORS filter.</p>
	 * 
	 * @param next The next http handler.
	 */
	public Filter(HttpHandler next) {
		super();
		this.next = next;
	}

	/**
	 * Sets the URL pattern that determines which requests will be filtered.
	 * 
	 * <p>This method will be called by undertow with the value of the parameter in the config.</p>
	 * 
	 * @param pattern The url pattern, which should be a valid regex string or {@code null}.
	 * 
	 * @see #setUrlPattern
	 * @see #DEFAULT_URL_PATTERN
	 */
	public void setUrlPattern(String pattern) {
		urlPattern = pattern;
	}

	/**
	 * Gets the URL pattern that determines which requests will be filtered.
	 * 
	 * @return The URL pattern, which should be a valid regex string, never {@code null}.
	 * 
	 * @see #setUrlPattern
	 * @see #DEFAULT_URL_PATTERN
	 */
	public String getUrlPattern() {
		return urlPattern != null ? urlPattern : DEFAULT_URL_PATTERN;
	}
	
	/**
	 * Sets the class name of the selected policy class.
	 * 
	 * <p>This method will be called by undertow with the value of the parameter in the config.</p>
	 * 
	 * @param name The name of the policy class to use, or {@code null}.
	 * 
	 * @see #getPolicyClass
	 * @see #DEFAULT_POLICY_CLASS
	 * @see AllowAll
	 * @see AllowMatching
	 * @see Whitelist
	 */
	public void setPolicyClass(String name) {
		policy = null;
		policyClass = name;
	}

	/**
	 * Gets the class name of the selected policy class.
	 * 
	 * @return The name of the policy class in use, never {@code null}.
	 * 
	 * @see #setPolicyClass
	 * @see #DEFAULT_POLICY_CLASS
	 * @see AllowAll
	 * @see AllowMatching
	 * @see Whitelist
	 */
	public String getPolicyClass() {
		return policyClass != null ? policyClass : DEFAULT_POLICY_CLASS;
	}

	/**
	 * Sets the policy parameter.
	 * 
	 * <p>This method will be called by undertow with the value of the parameter in the config.</p>
	 * 
	 * <p>The policy parameter is a String that is passed to the constructor when instantiating the policy class.</p>
	 * 
	 * @param value The string value, may be {@code null}.
	 * 
	 * @see #getPolicyParam
	 * @see #DEFAULT_POLICY_PARAM
	 */
	public void setPolicyParam(String value) {
		policy = null;
		policyParam = value;
	}

	/**
	 * Gets the policy parameter.
	 * 
	 * <p>The policy parameter is a String that is passed to the constructor when instantiating the policy class.</p>
	 * 
	 * @return The string value, may be empty but never {@code null}.
	 * 
	 * @see #setPolicyParam
	 * @see #DEFAULT_POLICY_PARAM
	 * @see AllowAll#AllowAll(String)
	 */
	public String getPolicyParam() {
		return policyParam != null ? policyParam : DEFAULT_POLICY_PARAM;
	}
	
	/**
	 * Sets the {@code exposeHeaders}.
	 * 
	 * <p>This method is called by Wildfly / JBoss EAP based on the config in standalone.xml.</p>
	 * 
	 * @param value The new value for the header, possibly {@code null}.
	 * 
	 * @see #getExposeHeaders
	 */
	public void setExposeHeaders(String value) {
		exposeHeaders = value;
	}

	/**
	 * Gets the configured {@code exposeHeaders}.
	 * 
	 * @return The configured setting, or the default.
	 * 
	 * @see #setExposeHeaders
	 * @see #DEFAULT_EXPOSE_HEADERS
	 */
	public String getExposeHeaders() {
		return exposeHeaders != null ? exposeHeaders : DEFAULT_EXPOSE_HEADERS;
	}

	/**
	 * Sets the {@code maxAge}.
	 * 
	 * <p>This method is called by Wildfly / JBoss EAP based on the config in standalone.xml.</p>
	 * 
	 * @param value The new value for the header, possibly {@code null}.
	 * 
	 * @see #getMaxAge
	 */
	public void setMaxAge(String value) {
		maxAge = value;
	}

	/**
	 * Gets the configured {@code maxAge}.
	 * 
	 * @return The configured setting, or the default.
	 * 
	 * @see #setMaxAge
	 * @see #DEFAULT_MAX_AGE
	 */
	public String getMaxAge() {
		return maxAge != null ? maxAge : DEFAULT_MAX_AGE;
	}

	/**
	 * Sets the {@code allowCredentials}.
	 * 
	 * <p>This method is called by Wildfly / JBoss EAP based on the config in standalone.xml.</p>
	 * 
	 * @param value The new value for the header, possibly {@code null}.
	 * 
	 * @see #getAllowCredentials
	 */
	public void setAllowCredentials(String value) {
		allowCredentials = value;
	}

	/**
	 * Gets the configured {@code allowCredentials}.
	 * 
	 * @return The configured setting, or the default.
	 *
	 * @see #setAllowCredentials
	 * @see #DEFAULT_ALLOW_CREDENTIALS
	 */
	public String getAllowCredentials() {
		return allowCredentials != null ? allowCredentials : DEFAULT_ALLOW_CREDENTIALS;
	}

	/**
	 * Sets the {@code allowMethods}.
	 * 
	 * <p>This method is called by Wildfly / JBoss EAP based on the config in standalone.xml.</p>
	 * 
	 * @param value The new value for the header, possibly {@code null}.
	 * 
	 * @see #getAllowMethods
	 */
	public void setAllowMethods(String value) {
		allowMethods = value;
	}

	/**
	 * Gets the configured {@code allowMethods}.
	 * 
	 * @return The configured setting, or the default.
	 * 
	 * @see #setAllowMethods
	 * @see #DEFAULT_ALLOW_METHODS
	 */
	public String getAllowMethods() {
		return allowMethods != null ? allowMethods : DEFAULT_ALLOW_METHODS;
	}

	/**
	 * Sets the {@code allowHeaders}.
	 * 
	 * <p>This method is called by Wildfly / JBoss EAP based on the config in standalone.xml.</p>
	 * 
	 * @param value The new value for the header, possibly {@code null}.
	 * 
	 * @see #getAllowMethods
	 */
	public void setAllowHeaders(String value) {
		allowHeaders = value;
	}

	/**
	 * Gets the configured {@code allowHeaders}.
	 * 
	 * @return The configured setting, or the default.
	 * 
	 * @see #setAllowMethods
	 * @see #DEFAULT_ALLOW_METHODS
	 */
	public String getAllowHeaders() {
		return allowHeaders != null ? allowHeaders : DEFAULT_ALLOW_HEADERS;
	}

	/**
	 * Creates the policy from the policy class with the given {@code name}, passing the given {@code param} to the constructor.
	 *  
	 * @param name The name of the policy class, never {@code null}.
	 * @param param The parameter to pass to the policy, possibly {@code null}.
	 * @return The created policy, or {@code null} if the policy class could not be found or instantiation failed.
	 */
	public Policy createPolicy(String name, String param) {
		Class<? extends Policy> P = null; 
		try {P = Class.forName(name).asSubclass(Policy.class);} 
		catch (ClassNotFoundException e) {
			LOG.log(Level.SEVERE, "undertow-cors-filter: Policy class " + name + " not found.", e);
			return null;
		}
		try {return P.getConstructor(String.class).newInstance(policyParam);} 
		catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			LOG.log(Level.SEVERE, "undertow-cors-filter: Unable to instantiate policy class " + name + " with parameter \"" + policyParam + "\".", e);
			return null;
		}
	}

	/**
	 * Handles the incoming request.
	 * 
	 * <p>This method tests whether the request given in {@code exchange} should be filtered, based
	 * on the request URL and the configured {@code urlPattern}, and if so, calls {@code applyPolicy}
	 * to apply the policy configured in {@code policyClass} and {@code plocyParam}.</p>
	 * 
	 * @param exchange The server exchange we got from Undertow, never {@code null}.
	 * 
	 * @see #applyPolicy
	 */
	@Override public void handleRequest(HttpServerExchange exchange) throws Exception {
		if (exchange.isInIoThread()) {
			// This code is executed by one of the XNIO I/O threads.
			// It is very important NOT to run anything that could block the thread. 
			exchange.dispatch(this);
			return;
	    }
		
		// This code is executed by a worker thread. It's save to do blocking I/O here.
		if (pattern == null) pattern = Pattern.compile(urlPattern);
		if (pattern.matcher(url(exchange)).matches()) {
			String origin = origin(exchange);
			boolean allowed = applyPolicy(exchange, origin);
			if (LOG.isLoggable(Level.INFO)) {
				LOG.info("undertow-cors-filter: CORS headers " + (allowed ? "" : "NOT ") + "added for origin " + origin);
			}
		}
		next.handleRequest(exchange);
	}

	/**
	 * Applies the policy configured in {@code policyClass} and {@code policyParam} and if the 
	 * given {@code origin} is allowed access, adds the response headers as configured.
	 *  
	 * @param exchange The server exchange we got from Undertow, never {@code null}.
	 * @param origin The origin that requests access, may be {@code null}.
	 * @return {@code true} if {@code origin} was allowed access, {@code false} otherwise.
	 */
	public boolean applyPolicy(HttpServerExchange exchange, String origin) {
		if (policy == null) policy = createPolicy(getPolicyClass(), getPolicyParam());
		if (policy != null && origin != null && policy.isAllowed(origin)) {
			if (!hasHeader(exchange, ACCESS_CONTROL_ALLOW_ORIGIN)) 		addHeader(exchange, ACCESS_CONTROL_ALLOW_ORIGIN, origin);
			if (!hasHeader(exchange, ACCESS_CONTROL_ALLOW_HEADERS)) 	addHeader(exchange, ACCESS_CONTROL_ALLOW_HEADERS, getAllowHeaders());
			if (!hasHeader(exchange, ACCESS_CONTROL_ALLOW_CREDENTIALS))	addHeader(exchange, ACCESS_CONTROL_ALLOW_CREDENTIALS, getAllowCredentials());
			if (!hasHeader(exchange, ACCESS_CONTROL_ALLOW_METHODS))		addHeader(exchange, ACCESS_CONTROL_ALLOW_METHODS, getAllowMethods());
			if (!hasHeader(exchange, ACCESS_CONTROL_EXPOSE_HEADERS)) 	addHeader(exchange, ACCESS_CONTROL_EXPOSE_HEADERS, getExposeHeaders());
			if (!hasHeader(exchange, ACCESS_CONTROL_MAX_AGE)) 			addHeader(exchange, ACCESS_CONTROL_MAX_AGE, getMaxAge());
			return true;
		}
		return false;
	}
	
	/**
	 * Gets the Origin header.
	 * 
	 * @param exchange The server exchange we got from Undertow, never {@code null}.
	 * 
	 * @return The Origin header string, may be {@code null}.
	 */
	protected String origin(HttpServerExchange exchange) {
		HeaderValues headers = ((HttpServerExchange) exchange).getRequestHeaders().get("Origin");
		return headers == null ? null : headers.peekFirst();
	}

	/**
	 * Gets the request URL including querystring.
	 * 
	 * @param exchange The server exchange we got from Undertow, never {@code null}.
	 * 
	 * @return The request URL, never {@code null}.
	 */
	protected String url(HttpServerExchange exchange) {
		return exchange.getRequestURL() + (exchange.getQueryString() == null ? "" : "?" + exchange.getQueryString());  
	}
	
	/**
	 * Checks whether the header with {@code name} is already present on the response.
	 * 
	 * @param exchange The server exchange we got from Undertow, never {@code null}.
	 * @param name The name of the header to check, never {@code null}.
	 * @return {@code true} if the header is already present, {@code false} otherwise.
	 */
	protected boolean hasHeader(HttpServerExchange exchange, String name) {
		return exchange.getResponseHeaders().get(name) != null;
	}
	
	/**
	 * Adds the response header with {@code name} and {@code value}.
	 * @param exchange The server exchange we got from Undertow, never {@code null}.
	 * @param name The name of the header to add, never {@code null}.
	 * @param value The value of the header to add, never {@code null}.
	 */
	protected void addHeader(HttpServerExchange exchange, String name, String value) {
		exchange.getResponseHeaders().add(HttpString.tryFromString(name), value);
	}
}
