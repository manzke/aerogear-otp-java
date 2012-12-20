package org.jboss.aerogear.security.otp;

import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.jboss.aerogear.security.otp.api.Hash;

public interface Otp {
	String now();

	boolean verify(String otp);

	public static abstract class OtpConfig<OtpType extends Otp, ConfigType extends OtpConfig<OtpType, ConfigType>> {
		protected Digits digits = Digits.SIX;
		protected Hash hash = Hash.SHA1;
		protected String secret;
		protected Clock clock = new Clock();

		public static <OtpType extends Otp, ConfigType extends OtpConfig<OtpType, ConfigType>> ConfigType type(
				Class<ConfigType> type) throws InstantiationException {
			try {
				return type.newInstance();
			} catch (IllegalAccessException e) {
				throw new InstantiationException(e.getMessage());
			}
		}

		protected OtpConfig() {
		}

		public abstract ConfigType self();

		public abstract OtpType build();

		public ConfigType secret(String secret) {
			this.secret = secret;
			return self();
		}

		public ConfigType clock(Clock clock) {
			this.clock = clock;
			return self();
		}

		public ConfigType digits(Digits digits) {
			this.digits = digits;
			return self();
		}

		public ConfigType hash(Hash hash) {
			this.hash = hash;
			return self();
		}
	}
}
