package com.stijndewitt.undertow.cors;

/**
 * A really simple CORS policy that just allows all requests, meaning the filter
 * will add CORS headers to all requests that have provided an Origin header.
 * 
 * @see #AllowAll(String)
 * @see #isAllowed
 * @see Policy
 */
public class AllowAll implements Policy {
	
	/**
	 * Creates a new {@code AllowAll} policy.
	 * 
	 * <p>For symmetry with other policy classes this constructor accepts a single 
	 * String parameter, but it is not used and is simply ignored.</p>
	 * 
	 * @param param A string parameter, will be ignored.
	 * 
	 * @see Filter#getPolicyClass
	 * @see Filter#setPolicyClass
	 * @see Filter#getPolicyParam
	 * @see Filter#setPolicyParam
	 */
	public AllowAll(String param) {
		// param is ignored for AllowAll policy
	}

	/**
	 * Indicates whether the given {@code origin} should be allowed access.
	 * 
	 * <p>This method in {@code AllowAll} simply always returns {@code true}.</p>
	 * 
	 * @param origin The origin String, may be {@code null}.
	 * 
	 * @return {@code true} if the origin is allowed (and CORS headers should be added), or {@code false} otherwise.
	 */
	@Override public boolean isAllowed(String origin) {
		return true;
	}
}
