package org.jboss.aerogear.security.otp;

import java.nio.charset.Charset;

import org.jboss.aerogear.security.otp.Otp.OtpAdapter;
import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Hash;

/**
 * @author Daniel Manzke
 */
public class Totp extends OtpAdapter {

	public Totp(String secret) {
		this(Totp.configure(secret));
	}

	public Totp(TotpConfig config) {
		super(config);
	}

	public static TotpConfig configure(String secret) {
		return new TotpConfig().secret(secret);
	}

	public static class TotpConfig extends OtpConfig<Totp, TotpConfig> {
		protected TotpConfig() {
			super();
			this.clock = new Clock();
		}
		
		@Override
		public TotpConfig secret(String secret) {
			this.key = secret.getBytes(Charset.forName("UTF-8"));
			if (key.length == 20)
				this.hash = Hash.SHA1;
			else if (key.length == 32)
				this.hash = Hash.SHA256;
			else if (key.length == 64)
				this.hash = Hash.SHA512;
			else
				throw new IllegalArgumentException(
						"Key length not supported, use a key of size of 20, 32 or 64 bytes");

			return this;
		}

		@Override
		public TotpConfig self() {
			return this;
		}

		public Totp build() {
			return new Totp(this);
		}
	}
}