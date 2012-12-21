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
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import org.jboss.aerogear.security.otp.Otp.OtpAdapter;
import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.jboss.aerogear.security.otp.api.Hash;
import org.jboss.aerogear.security.otp.api.Hex;

/**
 * @author Daniel Manzke
 */
public class Motp extends OtpAdapter {
	private final String pin;

	/**
	 * Initialize an OTP instance with the shared secret generated on
	 * Registration process
	 * 
	 * @param secret
	 *            Shared secret
	 */
	public Motp(String pin, String secret) {
		this(Motp.configure(secret, pin));
	}

	public Motp(MotpConfig config) {
		super(config);
		this.pin = config.pin;
	}

	/**
	 * Retrieves the current OTP
	 * 
	 * @return OTP
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Override
	public String now() {
		return hash(clock.getCurrentSeconds());
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
	@Override
	protected String hash(long epoch) {
		try {
			String base = Long.toString(epoch / 10) + new String(key, Charset.forName("UTF-8")) + pin;
			byte[] bytes = hash.digest(base.getBytes("UTF-8"));

			return Hex.encode(bytes).substring(0, digits.getLength());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return "";
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return "";
		}
	}
	
	@Override
	public boolean verify(String otp) {
		//make sure everything is in uppercase
		otp = otp.toUpperCase();
		long currentSeconds = clock.getCurrentSeconds();

		int pastResponse = Math.max(delayWindow, 0) * 10;

		for (int i = pastResponse; i >= 0; i = i - 10) {
			String candidate = hash(currentSeconds - i);
			if (otp.equals(candidate)) {
				return true;
			}
		}

		return false;
	}

	public static MotpConfig configure(String pin, String secret) {
		return new MotpConfig().pin(pin).secret(secret);
	}

	public static class MotpConfig extends OtpConfig<Motp, MotpConfig> {
		private String pin;

		protected MotpConfig() {
			super();
			this.hash = Hash.MD5;
			this.clock = new Clock();
			this.digits = Digits.SIX;
			this.tolerance = 3;
		}

		public MotpConfig pin(String pin) {
			this.pin = pin;
			return this;
		}
		
		@Override
		public MotpConfig secret(String secret) {
			this.key = secret.getBytes(Charset.forName("UTF-8"));
			return this;
		}

		@Override
		public MotpConfig self() {
			return this;
		}

		public Motp build() {
			return new Motp(this);
		}
	}
}
