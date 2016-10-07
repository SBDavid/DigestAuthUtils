package httpserver;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;

import config.AuthConfig;
import digestauth.DigestAuthenticator;
import digestauth.NonceManager;

public class DigestAuthFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) {
		String realm = filterConfig.getInitParameter("realm");
		String nonceExpireHours = filterConfig.getInitParameter("nonceExpireHours");
		String maxNoncePoolSize = filterConfig.getInitParameter("maxNoncePoolSize");
		String maxPreviousHashesSize = filterConfig.getInitParameter("maxPreviousHashesSize");
		String disallowLegacyAuth = filterConfig.getInitParameter("disallowLegacyAuth");
		
		if (!StringUtils.isEmpty(realm)) {
			AuthConfig.realm = realm;
		}
		
		if (!StringUtils.isEmpty(nonceExpireHours)) {
			AuthConfig.nonceExpireHours = Integer.parseInt(nonceExpireHours);
		}
		
		if (!StringUtils.isEmpty(maxNoncePoolSize)) {
			AuthConfig.maxNoncePoolSize = Integer.parseInt(maxNoncePoolSize);
		}
		
		if (!StringUtils.isEmpty(maxPreviousHashesSize)) {
			AuthConfig.maxPreviousHashesSize = Integer.parseInt(maxPreviousHashesSize);
		}
		
		if (!StringUtils.isEmpty(disallowLegacyAuth)) {
			AuthConfig.disallowLegacyAuth = Boolean.parseBoolean(disallowLegacyAuth);
		}
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		DigestAuthenticator auth = new DigestAuthenticator();
		
		String res = auth.authenticate((HttpServletRequest)request, (HttpServletResponse)response);
		
		// if user has not been authorized, let user input userName and password
		if (StringUtils.isEmpty(res) || res.equals("authRequird")) {
			
			String nonceStr = NonceManager.add();
			
			((HttpServletResponse)response).setHeader("WWW-Authenticate", "Digest realm=\"" + AuthConfig.realm + "\","
	        		+ "qop=auth,"
	        		+ "nonce=\"" + nonceStr + "\","
	        		+ "opaque=\"" + NonceManager.getOpaque(AuthConfig.realm, nonceStr) + "\"");
			
			((HttpServletResponse)response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			
		}
		// the password dose not match or the nonce is expired
		else if (res.equals("authFail")){
			((HttpServletResponse)response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.setContentType("text/html;charset=GB2312");
			PrintWriter out = response.getWriter();
			out.println("Auth Fail !");
			
			String nonceStr = NonceManager.add();
			
			((HttpServletResponse)response).setHeader("WWW-Authenticate", "Digest realm=\"" + AuthConfig.realm + "\","
	        		+ "qop=auth,"
	        		+ "nonce=\"" + nonceStr + "\","
	        		+ "opaque=\"" + NonceManager.getOpaque(AuthConfig.realm, nonceStr) + "\"");
		}
		else {
			chain.doFilter(request, response);
		}
	}

}
