package com.stijndewitt.undertow.cors;

import java.util.regex.Pattern;

/**
 * A regex-based CORS policy that allows all origins that match the regex given in the constructor.
 * 
 * @see #AllowMatching(String)
 * @see #isAllowed
 * @see Policy
 */
public class AllowMatching implements Policy {
	/**
	 * The default match pattern that will be used if no parameter was given in the constructor.
	 * 
	 * <p>When using {@code AllowMatching} without a parameter, it uses a regex that matches all 
	 * origin strings and is effectively the same as using the {@code AllowAll} policy.</p>
	 * 
	 * @see #AllowMatching(String)
	 * @see #getMatchPattern
	 */
	public static String DEFAULT_MATCH_PATTERN = "^.*$";
	
	private Pattern pattern;

	/**
	 * Creates a new {@code AllowMatching} policy.
	 * 
	 * @param param The regex string parameter, may be {@code null} or empty.
	 * 
	 * @see Filter#getPolicyClass
	 * @see Filter#setPolicyClass
	 * @see Filter#getPolicyParam
	 * @see Filter#setPolicyParam
	 */
	public AllowMatching(String param) {
		if (param == null || param.isEmpty()) param = DEFAULT_MATCH_PATTERN;
		pattern = Pattern.compile(param);
	}
	
	/**
	 * Indicates whether the given {@code origin} should be allowed access.
	 * 
	 * <p>This method in {@code AllowMatching} performs a regex match of the given {@code origin} 
	 * against the match pattern set when the policy was created and returns {@code true} if the
	 * given {@code origin} matched the pattern, or {@code false} otherwise.</p>
	 * 
	 * @param origin The origin String, may be {@code null}.
	 * 
	 * @return {@code true} if the given {@code origin} matched the pattern, {@code false} otherwise.
	 * 
	 * @see #getMatchPattern
	 */
	@Override public boolean isAllowed(String origin) {
		return origin != null && pattern.matcher(origin).matches();
	}
	
	/**
	 * Gets the match pattern currently in use by this policy.
	 * 
	 * <p>There is no setter for this parameter. It can only be set when the policy is created.</p>
	 * 
	 * @return The match pattern, never {@code null}.
	 * 
	 * @see #AllowMatching(String)
	 */
	public Pattern getMatchPattern() {
		return pattern;
	}
}
