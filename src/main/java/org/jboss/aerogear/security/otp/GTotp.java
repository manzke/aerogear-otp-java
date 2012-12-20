/*
 * JBoss, Home of Professional Open Source
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.aerogear.security.otp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.jboss.aerogear.security.otp.api.Hash;
import org.jboss.aerogear.security.otp.api.Hmac;

public final class GTotp implements Otp {

    private final String secret;
    private final Clock clock;
    private final Digits digits;
    private final Hash hash;
    private final int delayWindow;
    private static final int DEFAULT_DELAY_WINDOW = 1;

    /**
     * Initialize an OTP instance with the shared secret generated on Registration process
     *
     * @param secret Shared secret
     */
    public GTotp(String secret) {
    	this(secret, new Clock());
    }

    /**
     * Initialize an OTP instance with the shared secret generated on Registration process
     *
     * @param secret Shared secret
     * @param clock  Clock responsible for retrieve the current interval
     */
    public GTotp(String secret, Clock clock) {
        this.secret = secret;
        this.digits = Digits.SIX;
        this.hash = Hash.SHA1;
        this.clock = clock;
        this.delayWindow = DEFAULT_DELAY_WINDOW;
    }
    
    public GTotp(GTotpConfig config){
    	this.secret = config.secret;
    	this.clock = config.clock;
    	this.digits = config.digits;
    	this.hash = config.hash;
    	this.delayWindow = DEFAULT_DELAY_WINDOW;
    }

    /**
     * Prover - To be used only on the client side
     * Retrieves the encoded URI to generated the QRCode required by Google Authenticator
     *
     * @param name Account name
     * @return Encoded URI
     */
    public String uri(String name) {
        try {
            return String.format("otpauth://totp/%s?secret=%s", URLEncoder.encode(name, "UTF-8"), secret);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    /**
     * Retrieves the current OTP
     *
     * @return OTP
     */
    public String now() {
        return leftPadding(hash(clock.getCurrentInterval()));
    }

    /**
     * Verifier - To be used only on the server side
     * <p/>
     * Taken from Google Authenticator with small modifications from
     * {@see <a href="http://code.google.com/p/google-authenticator/source/browse/src/com/google/android/apps/authenticator/PasscodeGenerator.java?repo=android#212">PasscodeGenerator.java</a>}
     * <p/>
     * Verify a timeout code. The timeout code will be valid for a time
     * determined by the interval period and the number of adjacent intervals
     * checked.
     *
     * @param otp Timeout code
     * @return True if the timeout code is valid
     *         <p/>
     *         Author: sweis@google.com (Steve Weis)
     */
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

    private int hash(long interval) {
        byte[] bytes = new byte[0];
        try {
            //Base32 encoding is just a requirement for google authenticator. We can remove it on the next releases.
        	byte[] challenge = ByteBuffer.allocate(8).putLong(interval).array();
        	bytes = new Hmac(hash, Base32.decode(secret)).digest(challenge);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return -1;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return -1;
        } catch (Base32.DecodingException e) {
            e.printStackTrace();
            return -1;
        }
        
        return bytesToInt(bytes);
    }

    private int bytesToInt(byte[] hash) {
        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        return binary % digits.getValue();
    }

    private String leftPadding(int otp) {
        return String.format("%0"+digits.getLength()+"d", otp);
    }
    
    public static GTotpConfig configure(String secret){
    	return new GTotpConfig().secret(secret);
    }
    
	public static class GTotpConfig extends Config<GTotp, GTotpConfig> {
		protected GTotpConfig() {
			super();
			this.digits = Digits.SIX;
			this.hash = Hash.SHA1;
			this.clock = new Clock();
		}
		
		@Override
		public GTotpConfig self() {
			return this;
		}
		
		public GTotp build(){
			return new GTotp(this);
		}
	}
}
