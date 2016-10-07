package digestauth;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;

import config.AuthConfig;

public class DigestAuthenticator {
	
	public String authenticate(HttpServletRequest request, HttpServletResponse response) {
		
		String auth = request.getHeader("Authorization");
		
		// Check if the authorization header is present
		if (StringUtils.isEmpty(auth)) {
			return "authRequird";
		}
		
		 // Make sure we're getting a digest authentication request
        int sp = auth.indexOf (' ');
        if (sp == -1 || !auth.substring(0, sp).equals ("Digest")) {
            return "authRequird";
        }
		
        Map<String,String> authParams = Utils.parseHeader(auth);
        
        String targetUser = authParams.get("username");
        String ha1 = Utils.gethAuthToken();
        String qop = authParams.get("qop");
        String reqURI = authParams.get("uri");
        
        String ha2 = Utils.calculateMD5(request.getMethod() + ":" + reqURI);
        
        String nonce = authParams.get("nonce");
        String clientResponse = authParams.get("response");
        
        // Make sure we haven't processed the same hash before
        if (PreviousHashesManager.isDuplicatedHash(clientResponse)) {
        	return "authFail";
        }
        
        // Make sure nonce is not expired
        if (!NonceManager.validateNonce(nonce)) {
        	return "authFail";
        }
        
        // Mark this hash as processed
        PreviousHashesManager.addPreviousHash(clientResponse);
        
        String serverResponse;
        
        if (qop == null || qop.length() < 1) {
        	if (AuthConfig.disallowLegacyAuth) {
        		return "authFail";
        	}
        	
            serverResponse = Utils.calculateMD5(ha1 + ":" + nonce + ":" + ha2);

        } else {
            String nonceCount = authParams.get("nc");
            String clientNonce = authParams.get("cnonce");

            serverResponse = Utils.calculateMD5(ha1 + ":" + nonce + ":"
                    + nonceCount + ":" + clientNonce + ":" + qop + ":" + ha2);

        }
        
		return clientResponse.equals(serverResponse) ? "authSuccess" : "authFail";
	}
}
