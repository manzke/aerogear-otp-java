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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Hash;
import org.jboss.aerogear.security.otp.api.Hex;

/**
 * @author Daniel Manzke
 */
public class Motp implements Otp {

    private final String secret;
    private final Clock clock;
	private final String pin;
	private final Hash hash;
	private final int delayWindow;
    private static final int DEFAULT_DELAY_WINDOW = 3; //latest 60 seconds -> motp.sourceforge.net tells 3 minutes past/future

    /**
     * Initialize an OTP instance with the shared secret generated on Registration process
     *
     * @param secret Shared secret
     */
    public Motp(String pin, String secret) {
    	this(pin, secret, new Clock());
    }

    /**
     * Initialize an OTP instance with the shared secret generated on Registration process
     *
     * @param secret Shared secret
     * @param clock  Clock responsible for retrieve the current interval
     */
    public Motp(String pin, String secret, Clock clock) {
    	this((MotpConfig) new MotpConfig().pin(pin).secret(secret).clock(clock));
    }
    
    public Motp(MotpConfig config){
    	this.secret = config.secret;
    	this.clock = config.clock;
    	this.hash = config.hash;
    	this.pin = config.pin;
    	this.delayWindow = DEFAULT_DELAY_WINDOW;
    }


    /**
     * Retrieves the current OTP
     *
     * @return OTP
     * @throws NoSuchAlgorithmException 
     * @throws UnsupportedEncodingException 
     */
    public String now() {
    	return generate(clock.getCurrentSeconds());
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
        long currentSeconds = clock.getCurrentSeconds();

        int pastResponse = Math.max(delayWindow, 0) * 10;

        for (int i = pastResponse; i >= 0; i = i - 10) {
            String candidate = generate(currentSeconds - i);
            if (otp.equalsIgnoreCase(candidate)) {
                return true;
            }
        }
        
        return false;
    }
    
    private String generate(long epoch) {
    	try {
			String base = Long.toString(epoch / 10) + secret + pin;
			MessageDigest digest = MessageDigest.getInstance(hash.toString());
			byte[] bytes = digest.digest(base.getBytes("UTF-8"));
			
			return Hex.encode(bytes).substring(0,6);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return "";
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return "";
		}
    }
    
    public static MotpConfig configure(String secret, String pin){
    	return new MotpConfig().pin(pin).secret(secret);
    }
    
	public static class MotpConfig extends Config<Motp, MotpConfig> {
		private String pin;
		protected MotpConfig() {
			super();
			this.hash = Hash.MD5;
			this.clock = new Clock();
		}
		
		public MotpConfig pin(String pin){
			this.pin = pin;
			return this;
		}
		
		@Override
		public MotpConfig self() {
			return this;
		}
		
		public Motp build(){
			return new Motp(this);
		}
	}
}
