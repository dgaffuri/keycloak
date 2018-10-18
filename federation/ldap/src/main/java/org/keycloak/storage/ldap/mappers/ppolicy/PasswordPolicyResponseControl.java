/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.storage.ldap.mappers.ppolicy;

import java.io.IOException;
import java.util.Objects;

import javax.naming.NamingException;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.xml.bind.DatatypeConverter;

import org.jboss.logging.Logger;

/**
 * Helper class to decode password policy response control. Examples of BER data from response control are:
 * <ul>
 * <li>3003810102: error changeAfterReset
 * <li>3006A00481024E20: warning graceAuthNsRemaining 20000
 * <li>3009A00480022710810102: warning timeBeforeExpiration 10000, error changeAfterReset
 * </ul>
 * 
 * @author <a href="mailto:da.gaffuri@gmail.com">Daniele Gaffuri</a>
 */
public class PasswordPolicyResponseControl {

    public static final String OID = "1.3.6.1.4.1.42.2.27.8.5.1";
    
    private static final Logger logger = Logger.getLogger(PasswordPolicyResponseControl.class);

    // minimal BER decoder
    private static final class BerDecoder {

        private byte buffer[];
        private int offset;

        private BerDecoder(final byte buffer[]) {
        	Objects.requireNonNull(buffer, "buffer");
            this.buffer = buffer;
        }

        private int parseLength() throws IOException {
            int length = parseByte();
            if ((length & 0x80) == 0x80) {
                length &= 0x7f;
                if (length <= 0 || length > 4) {
                    throw new IOException(String.format("invalid length bytes %d", length));
                }
                if (buffer.length - offset < length) {
                    throw new IOException(String.format("buffer underflow, length bytes is %d but only %d bytes remain", length, buffer.length - offset));
                }
                int retval = 0;
                for( int i = 0; i < length; i++) {
                    retval = (retval << 8) + (buffer[offset++] & 0xff);
                }
                length = retval;
                if (length < 0) {
                	throw new IOException(String.format("invalid length %d", length));
                }
            }
            return length;
        }

        private int parseByte() throws IOException {
            int peeked = peekByte();
            offset++;
            return peeked;
        }

        private int peekByte() throws IOException {
            if (buffer.length - offset < 1) {
                throw new IOException("buffer underflow, no bytes remain");
            }
            return buffer[offset] & 0xff;
        }

        private int parseInteger() throws IOException {
            int length = parseLength();
            if (length > 4) {
            	throw new IOException(String.format("invalid integer length %d", length));
            }
            if (length > buffer.length - offset) {
                throw new IOException(String.format("buffer underflow, integer length is %d but only %d bytes remain", length, buffer.length - offset));
            }
            byte fb = buffer[offset++];
            int value = 0;
            value = fb & 0x7F;
            for(int i = 1; i < length; i++) {
                value <<= 8;
                value |= (buffer[offset++] & 0xff);
            }
            if ((fb & 0x80) == 0x80) {
                value = -value;
            }
            return value;
        }

        private boolean remaining() {
            return buffer.length - offset > 0;
        }
    }
    
    /**
     * Factory method to obtain a password policy response control, if any, from LDAP context.
     * 
     * @param context the LDAP context
     * @return the response control or {@code null} if no control is present or the encoded value can't be decoded
     * @throws NamingException if failing to retrieve response controls from LDAP context
     */
    public static PasswordPolicyResponseControl getInstance(final LdapContext context) throws NamingException {
    	Objects.requireNonNull(context, "context");
        try {
            Control[] controls = context.getResponseControls();
            if (controls != null) {
	            for (int i = 0; i < controls.length; i++) {
	                if (PasswordPolicyResponseControl.OID.equals(controls[i].getID())) {
	                    return getInstance(controls[i].getEncodedValue());
	                }
	            }
            }
        } catch (NamingException e) {
            if (logger.isDebugEnabled()) {
                logger.debugf(e, "Error retrieving response controls");
            }
            throw e;
        }
    	return null;
    }
    
    /**
     * Factory method to obtain a password policy response control from BER encoded response control value.
     * 
     * @param encodedValue the BER encoded response control value
     * @return the response control or {@code null} if the encoded value can't be decoded
     */
    public static PasswordPolicyResponseControl getInstance(final byte[] encodedValue) {
    	Objects.requireNonNull(encodedValue, "encodedValue");
        PasswordPolicyResponseControl responseControl = null;
        try {
           	responseControl = new PasswordPolicyResponseControl();
        	decode(encodedValue, responseControl);
        } catch (Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debugf(e, "Error decoding password policy response control [0x%s]", DatatypeConverter.printHexBinary(encodedValue));
            }
            responseControl = null;
        }
    	return responseControl;
    }
    
    private static void decode(final byte[] controlValue, final PasswordPolicyResponseControl response) throws Exception {
        BerDecoder decoder = new BerDecoder(controlValue);
        if (!decoder.remaining()) {
        	return;
        }
		decoder.parseByte();
		decoder.parseLength();
		if (decoder.remaining()) {
			int type = decoder.peekByte() ^ 0x80;
			if (type == 0x20 ) {
				decoder.parseByte();
				decoder.parseLength();
				int warning = decoder.parseByte() ^ 0x80;
				int value = decoder.parseInteger();
				if (warning >= 0 && warning < Warning.values().length) {
					response.warning = Warning.values()[warning];
					response.warningValue = value;
				}
			}
		}
		if (decoder.remaining()) {
			int type = decoder.parseByte() ^ 0x80;
			if (type == 1) {
				int error = decoder.parseInteger();
				if (error >= 0 && error < Error.values().length) {
					response.error = Error.values()[error];
				}
			}
		}
    }
    
    /**
     * Warning codes.
     */
    public enum Warning {
        timeBeforeExpiration,
        graceAuthNsRemaining
    }
    
    /**
     * Error codes.
     */
    public enum Error {
        passwordExpired,
        accountLocked,
        changeAfterReset,
        passwordModNotAllowed,
        mustSupplyOldPassword,
        insufficientPasswordQuality,
        passwordTooShort,
        passwordTooYoung,
        passwordInHistory
    };
    
    private Warning warning ;
	private int warningValue;
    private Error error;

    // avoid instantiation
    private PasswordPolicyResponseControl() {
    }

    /**
     * @return the warning or {@code null}
     */
	public Warning getWarning() {
		return warning;
	}

    /**
     * @return the warning value or 0 if no warning is present
     */
	public int getWarningValue() {
		return warningValue;
	}

    /**
     * @return the error or {@code null}
     */
	public Error getError() {
		return error;
	}

    @Override
	public String toString() {
    	StringBuilder sb = new StringBuilder();
    	if (warning != null) {
    		sb.append(warning + ":" + warningValue).append(',');
    	}
    	if (error != null) {
    		sb.append(error).append(',');
    	}
    	int length = sb.length();
    	if (length > 0) {
    		sb.deleteCharAt(sb.length() - 1);
    	}
    	sb.insert(0, "PasswordPolicyResponseControl[");
    	sb.append(']');
		return sb.toString();
	}
}
