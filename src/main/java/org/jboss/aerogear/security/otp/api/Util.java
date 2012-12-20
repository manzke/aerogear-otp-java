package org.jboss.aerogear.security.otp.api;

public class Util {
	public static int bytesToInt(byte[] hash, Digits digits) {
		// put selected bytes into result int
		int offset = hash[hash.length - 1] & 0xf;

		int binary = ((hash[offset] & 0x7f) << 24)
				| ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

		return binary % digits.getValue();
	}

	public static String leftPadding(int otp, Digits digits) {
		return String.format("%0" + digits.getLength() + "d", otp);
	}
}
