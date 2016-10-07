package config;

public class AuthConfig {
	public static String realm = "test.com";
	
	public static int nonceExpireHours = 1;
	public static int maxNoncePoolSize = 1000;
	
	public static int maxPreviousHashesSize = 5000;
	
	/**
	 * Prevent insecure legacy digest auth calls
	 */
	public static boolean disallowLegacyAuth = true;
}
