package digestauth;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import config.AuthConfig;
import digestauth.bean.Nonce;

public class NonceManager {
	private static Map<String, Nonce> noncePool = new HashMap<String, Nonce>();
	
	private static String generate() {
		return UUID.randomUUID().toString();
	}
	
	@SuppressWarnings("rawtypes")
	public static String add() {
		
		synchronized (noncePool) {
			
			removeExpiredNonce();
			
			if (noncePool.size() >= AuthConfig.maxNoncePoolSize) {
				return null;
			}
			
			// add nonce object
			String nonceStr = generate();
			noncePool.put(nonceStr, new Nonce(nonceStr));
			return nonceStr;
		}
	}
	
	public static boolean validateNonce(String nonceStr) {
		
		synchronized (noncePool) {
			
			removeExpiredNonce();
			
			return noncePool.containsKey(nonceStr);
		}
	}
	
	
	/**
	 * remove expired nonce if size is too large
	 */
	@SuppressWarnings("rawtypes")
	private static void removeExpiredNonce() {
		if (noncePool.size() >= AuthConfig.maxNoncePoolSize) {
			Iterator iter = noncePool.entrySet().iterator();
				while (iter.hasNext()) {
					Map.Entry entry = (Map.Entry) iter.next();
					
					if (((LocalDateTime)entry.getValue()).isBefore(LocalDateTime.now())) {
						noncePool.remove(entry.getKey());
					}
				}
		}
	}
	
	public static String getOpaque(String domain, String nonce) {
        return Utils.calculateMD5(domain + nonce);
    }
}
