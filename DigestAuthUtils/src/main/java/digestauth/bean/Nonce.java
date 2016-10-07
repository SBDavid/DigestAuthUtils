package digestauth.bean;

import java.time.LocalDateTime;

import config.AuthConfig;

public class Nonce {
	private String nonceStr;
	private LocalDateTime expireTime;
	public Nonce(String nonceStr) {
		this.nonceStr = nonceStr;
		this.expireTime = LocalDateTime.now().plusHours(AuthConfig.nonceExpireHours);
	}
	public String getNonceStr() {
		return nonceStr;
	}
	public void setNonceStr(String nonceStr) {
		this.nonceStr = nonceStr;
	}
	public LocalDateTime getExpireTime() {
		return expireTime;
	}
	public void setExpireTime(LocalDateTime expireTime) {
		this.expireTime = expireTime;
	}
}
