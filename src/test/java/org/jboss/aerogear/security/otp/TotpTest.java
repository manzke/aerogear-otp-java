package org.jboss.aerogear.security.otp;

import static junit.framework.Assert.assertEquals;
import static org.mockito.Mockito.when;

import org.jboss.aerogear.security.otp.Otp.OtpConfig;
import org.jboss.aerogear.security.otp.Totp.TotpConfig;
import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class TotpTest {
    @Mock
    private Clock clock;
    private TotpConfig config;
    
    public static final String key20 = "12345678901234567890";
    public static final String key32 = key20 + "123456789012";
    public static final String key64 = key20 + key20 + key20 + "1234";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        config = OtpConfig.type(TotpConfig.class).clock(clock).digits(Digits.EIGHT);
    }
    
    private void setTimeTo(long milliseconds) {
    	when(clock.getCurrentInterval()).thenReturn(milliseconds / 1000 / 30);
    }
    
    @Test
    public void testKey20Time1() throws Exception {
    	setTimeTo(59000L);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("token doesn't match", "94287082", token);
    }
    
    @Test
    public void testKey20Time2() throws Exception {
    	setTimeTo(1111111109000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("token doesn't match", "07081804", token);
    }
    
    @Test
    public void testKey20Time3() throws Exception {
    	setTimeTo(1111111111000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("token doesn't match", "14050471", token);
    }
    
    @Test
    public void testKey20Time4() throws Exception {
    	setTimeTo(1234567890000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("token doesn't match", "89005924", token);
    }
    
    @Test
    public void testKey20Time5() throws Exception {
    	setTimeTo(2000000000000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("token doesn't match", "69279037", token);
    }
    
    @Test
    public void testKey20Time6() throws Exception {
    	setTimeTo(20000000000000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("token doesn't match", "65353130", token);
    }
    
    @Test
    public void testKey32Time1() throws Exception {
    	setTimeTo(59000L);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("token doesn't match", "46119246", token);
    }
    
    @Test
    public void testKey32Time2() throws Exception {
    	setTimeTo(1111111109000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("token doesn't match", "68084774", token);
    }
    
    @Test
    public void testKey32Time3() throws Exception {
    	setTimeTo(1111111111000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("token doesn't match", "67062674", token);
    }
    
    @Test
    public void testKey32Time4() throws Exception {
    	setTimeTo(1234567890000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("token doesn't match", "91819424", token);
    }
    
    @Test
    public void testKey32Time5() throws Exception {
    	setTimeTo(2000000000000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("token doesn't match", "90698825", token);
    }
    
    @Test
    public void testKey32Time6() throws Exception {
    	setTimeTo(20000000000000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("token doesn't match", "77737706", token);
    }
    
    
    @Test
    public void testKey64Time1() throws Exception {
    	setTimeTo(59000L);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("token doesn't match", "90693936", token);
    }
    
    @Test
    public void testKey64Time2() throws Exception {
    	setTimeTo(1111111109000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("token doesn't match", "25091201", token);
    }
    
    @Test
    public void testKey64Time3() throws Exception {
    	setTimeTo(1111111111000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("token doesn't match", "99943326", token);
    }
    
    @Test
    public void testKey64Time4() throws Exception {
    	setTimeTo(1234567890000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("token doesn't match", "93441116", token);
    }
    
    @Test
    public void testKey64Time5() throws Exception {
    	setTimeTo(2000000000000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("token doesn't match", "38618901", token);
    }
    
    @Test
    public void testKey64Time6() throws Exception {
    	setTimeTo(20000000000000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("token doesn't match", "47863826", token);
    }
}
