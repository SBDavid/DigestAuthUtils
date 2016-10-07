package config;

public class AuthConfig {
	public final static String realm = "test.com";
	
	public final static int nonceExpireHours = 1;
	public final static int maxNoncePoolSize = 1000;
	
	public final static int maxPreviousHashesSize = 5000;
	
	/**
	 * Prevent insecure legacy digest auth calls
	 */
	public final static boolean disallowLegacyAuth = true;
}
