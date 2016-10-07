package digestauth;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import config.AuthConfig;

public class Utils {
	
	// Encoding to use for converting strings
	private static final String transportCharacterEncoding = "ISO-8859-1";
	
	/**
     * Gets the Authorization header string minus the "AuthType" and returns a
     * hashMap of keys and values
     *
     * @param headerString
     * @return
     */
    public static Map<String, String> parseHeader(String headerString) {
        // Separate out the part of the string which tells you which Auth scheme is it
        String headerStringWithoutScheme = headerString.substring(headerString.indexOf(" ") + 1).trim();
        HashMap<String, String> values = new HashMap<String, String>();
        String keyValueArray[] = headerStringWithoutScheme.split(",");
        for (String keyval : keyValueArray) {
            if (keyval.contains("=")) {
                String key = keyval.substring(0, keyval.indexOf("="));
                String value = keyval.substring(keyval.indexOf("=") + 1);
                values.put(key.trim(), value.replaceAll("\"", "").trim());
            }
        }
        return values;
	}
    
    public static String gethAuthToken() {
    	return calculateAuthToken("martinzh", "ict645");
    };
    
    public static String calculateAuthToken(String username, String password) {
    	String token = username + ":" + AuthConfig.realm + ":" + password;
    	return calculateMD5(token);
    }
    
    public static String calculateMD5(String target) {
		try {
			return calculateMD5(target.getBytes(transportCharacterEncoding));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
    }
    
    private static String calculateMD5(byte[] originalArray) {
 	   try {
 	        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
 	        byte[] array = md.digest(originalArray);
 	        StringBuffer sb = new StringBuffer();
 	        for (int i = 0; i < array.length; ++i) {
 	          sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1,3));
 	       }
 	        return sb.toString();
 	    } catch (java.security.NoSuchAlgorithmException e) {
 	    	// We should never be here
 	    	e.printStackTrace();
 	    }
 	    return null;
 	}
}
