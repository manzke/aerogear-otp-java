package org.jboss.aerogear.security.otp;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.jboss.aerogear.security.otp.api.Hash;
import org.jboss.aerogear.security.otp.api.Hmac;

import static org.jboss.aerogear.security.otp.api.Util.*;

/**
 * @author Daniel Manzke
 */
public class Totp implements Otp {
    private final byte[] key;
    private final Clock clock;
    private final Digits digits;
    private final Hash hash;
    private final int delayWindow;
    
    private static final int DEFAULT_DELAY_WINDOW = 3;
    
    public Totp(String secret) {
    	this.key = secret.getBytes(Charset.forName("UTF-8"));
        if (key.length == 20) this.hash = Hash.SHA1;
        else if (key.length == 32) this.hash = Hash.SHA256;
        else if (key.length == 64) this.hash = Hash.SHA512;
        else throw new IllegalArgumentException("Key length not supported, use a key of size of 20, 32 or 64 bytes");
        this.digits = Digits.EIGHT;
        this.delayWindow = DEFAULT_DELAY_WINDOW;
        this.clock = new Clock();
    }

    public Totp(TotpConfig config) {
    	this.key = config.secret.getBytes(Charset.forName("UTF-8"));
        if (key.length == 20) this.hash = Hash.SHA1;
        else if (key.length == 32) this.hash = Hash.SHA256;
        else if (key.length == 64) this.hash = Hash.SHA512;
        else throw new IllegalArgumentException("Key length not supported, use a key of size of 20, 32 or 64 bytes");
        this.digits = config.digits;
        this.delayWindow = DEFAULT_DELAY_WINDOW;
        this.clock = config.clock;
	}
    
    @Override
    public String now() {
    	return leftPadding(hash(clock.getCurrentInterval()), digits);
    }

    /**
     * This method generates a TOTP value
     *
     * @param time the current time in millis
     * @return a numeric String in base 10 that includes
     *         truncationDigits digits
     */
    private int hash(long interval) {
        try {
			byte[] challenge = ByteBuffer.allocate(8).putLong(interval).array();
			byte[] calculatedHash = new Hmac(hash, this.key).digest(challenge);

			// put selected bytes into result int
			return bytesToInt(calculatedHash, digits);
		} catch (java.security.InvalidKeyException e) {
			e.printStackTrace();
			return -1;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return -1;
		}
    }
    
    public boolean verify(String otp) {
        long code = Long.parseLong(otp);
        long currentInterval = clock.getCurrentInterval();

        int pastResponse = Math.max(delayWindow, 0);

        for (int i = pastResponse; i >= 0; --i) {
            int candidate = hash(currentInterval - i);
            if (candidate == code) {
                return true;
            }
        }
        return false;
    }
    
    public static TotpConfig configure(String secret){
    	return new TotpConfig().secret(secret);
    }
    
    public static class TotpConfig extends Config<Totp, TotpConfig> {
		protected TotpConfig() {
			super();
			this.clock = new Clock();
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