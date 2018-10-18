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

import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.storage.ldap.mappers.ppolicy.PasswordPolicyResponseControl.Error;
import org.keycloak.storage.ldap.mappers.ppolicy.PasswordPolicyResponseControl.Warning;

/**
 * @author <a href="mailto:da.gaffuri@gmail.com">Daniele Gaffuri</a>
 */
public class PasswordPolicyResponseControlTest {

	@Test
	public void testErrors() {
		for (Error error : Error.values()) {
			testError(error);
		}
	}
	
	@Test
	public void testWarnings() {
		for (Warning warning : Warning.values()) {
			testWarning(warning);
		}
	}
	
	@Test
	public void testBoth() {
		testBoth(Warning.timeBeforeExpiration, Error.accountLocked);
		testBoth(Warning.graceAuthNsRemaining, Error.passwordExpired);
	}
	
	@Test
	public void testUnknownError() {
		testUnknownError(Error.values().length);
	}
	
	@Test
	public void testUnknownWarning() {
		testUnknownWarning(Warning.values().length);
	}
	
	@Test
	public void testVoid() {
		PasswordPolicyResponseControl control = getControl("");
		Assert.assertNotNull(control);
		Assert.assertNull(control.getError());
		Assert.assertNull(control.getWarning());
		Assert.assertEquals(0, control.getWarningValue());
	}
	
	@Test
	public void testInvalid() {
		// buffer underflow, integer length set to 2 but only 1 byte next
		PasswordPolicyResponseControl control = getControl("810201");
		Assert.assertNull(control);
	}
	
	private void testError(final Error error) {
		String value = String.format("8101%02x", error.ordinal());
		PasswordPolicyResponseControl control = getControl(value);
		Assert.assertNotNull(control);
		Assert.assertEquals(error, control.getError());
		Assert.assertNull(control.getWarning());
		Assert.assertEquals(0, control.getWarningValue());
	}
	
	private void testWarning(final Warning warning) {
		int warningValue = 10000 * (warning.ordinal() + 1);
		String value = String.format("A004%02x02%04x", warning.ordinal() | 0x80, warningValue);
		PasswordPolicyResponseControl control = getControl(value);
		Assert.assertNotNull(control);
		Assert.assertEquals(warning, control.getWarning());
		Assert.assertEquals(warningValue, control.getWarningValue());
		Assert.assertNull(control.getError());
	}
	
	private void testBoth(final Warning warning, final Error error) {
		int warningValue = 10000 * (warning.ordinal() + 1);
		String value = String.format("A004%02x02%04x8101%02x", warning.ordinal() | 0x80, warningValue, error.ordinal());
		PasswordPolicyResponseControl control = getControl(value);
		Assert.assertNotNull(control);
		Assert.assertEquals(error, control.getError());
		Assert.assertEquals(warning, control.getWarning());
		Assert.assertEquals(warningValue, control.getWarningValue());
	}
	
	private void testUnknownError(final int errorOrdinal) {
		String value = String.format("8101%02x", errorOrdinal);
		PasswordPolicyResponseControl control = getControl(value);
		Assert.assertNotNull(control);
		Assert.assertNull(control.getError());
		Assert.assertNull(control.getWarning());
		Assert.assertEquals(0, control.getWarningValue());
	}
	
	private void testUnknownWarning(final int warningOrdinal) {
		String value = String.format("A004%02x02%04x", warningOrdinal | 0x80, 10000 * (warningOrdinal + 1));
		PasswordPolicyResponseControl control = getControl(value);
		Assert.assertNotNull(control);
		Assert.assertNull(control.getWarning());
		Assert.assertEquals(0, control.getWarningValue());
		Assert.assertNull(control.getError());
	}
	
	private PasswordPolicyResponseControl getControl(final String control) {
		// prefix with sequence (0x30) and length
		return PasswordPolicyResponseControl.getInstance(DatatypeConverter.parseHexBinary(String.format("30%02x%s", control.length() / 2, control)));
	}
}
