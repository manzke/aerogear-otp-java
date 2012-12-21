package org.jboss.aerogear.security.otp.api;

public class Hex {
	public static final char[] DIGITS = { '0', '1', '2', '3', '4', '5', '6',
		'7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	public static String encode(byte[] raw) {
		int length = raw.length;
		char[] hex = new char[length * 2];
		for (int i = 0; i < length; i++) {
			int value = (raw[i] + 256) % 256;
			int highIndex = value >> 4;
			int lowIndex = value & 0x0f;
			int j = i * 2;
			hex[j + 0] = DIGITS[highIndex];
			hex[j + 1] = DIGITS[lowIndex];
		}
		return new String(hex);
	}
}
