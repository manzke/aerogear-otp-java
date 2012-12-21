package org.jboss.aerogear.security.otp;

import static org.jboss.aerogear.security.otp.api.Util.bytesToInt;
import static org.jboss.aerogear.security.otp.api.Util.leftPadding;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.jboss.aerogear.security.otp.api.Hash;
import org.jboss.aerogear.security.otp.api.Hmac;

public interface Otp {
	
	int DEFAULT_DELAY_WINDOW = 1;
	
	String now();

	boolean verify(String otp);
	
	public static abstract class OtpAdapter implements Otp {
		protected final Clock clock;
		protected final Digits digits;
		protected final Hash hash;
		protected final int delayWindow;
		protected final byte[] key;
		
		public <ConfigType extends OtpConfig<?, ?>> OtpAdapter(ConfigType config){
			this.clock = config.clock;
			this.digits = config.digits;
			this.hash = config.hash;
			this.key = config.key;
			this.delayWindow = config.tolerance;
		}
		
		/**
		 * Retrieves the current OTP
		 * 
		 * @return OTP
		 */
		public String now() {
			return hash(clock.getCurrentInterval());
		}
		
		/**
		 * Verifier - To be used only on the server side
		 * <p/>
		 * Taken from Google Authenticator with small modifications from {@see <a
		 * href=
		 * "http://code.google.com/p/google-authenticator/source/browse/src/com/google/android/apps/authenticator/PasscodeGenerator.java?repo=android#212"
		 * >PasscodeGenerator.java</a>}
		 * <p/>
		 * Verify a timeout code. The timeout code will be valid for a time
		 * determined by the interval period and the number of adjacent intervals
		 * checked.
		 * 
		 * @param otp
		 *            Timeout code
		 * @return True if the timeout code is valid
		 *         <p/>
		 *         Author: sweis@google.com (Steve Weis)
		 */
		public boolean verify(String otp) {
			//make sure everything is in uppercase
			otp = otp.toUpperCase();
			long currentInterval = clock.getCurrentInterval();

			int pastResponse = Math.max(delayWindow, 0);

			for (int i = pastResponse; i >= 0; --i) {
				String candidate = hash(currentInterval - i);
				if (otp.equals(candidate)) {
					return true;
				}
			}
			
			return false;
		}
		
		protected String hash(long interval) {
			byte[] bytes = new byte[0];
			try {
				byte[] challenge = ByteBuffer.allocate(8).putLong(interval).array();
				bytes = new Hmac(hash, key).digest(challenge);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return "";
			} catch (InvalidKeyException e) {
				e.printStackTrace();
				return "";
			} 

			return leftPadding(bytesToInt(bytes, digits), digits);
		}
	}

	public static abstract class OtpConfig<OtpType extends Otp, ConfigType extends OtpConfig<OtpType, ConfigType>> {
		protected Digits digits = Digits.SIX;
		protected Hash hash = Hash.SHA1;
		protected byte[] key;
		protected Clock clock = new Clock();
		protected int tolerance = DEFAULT_DELAY_WINDOW;

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

		public abstract OtpType build() throws Exception;

		public abstract ConfigType secret(String secret) throws Exception;
		
		public ConfigType tolerance(int tolerance){
			this.tolerance = tolerance;
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
