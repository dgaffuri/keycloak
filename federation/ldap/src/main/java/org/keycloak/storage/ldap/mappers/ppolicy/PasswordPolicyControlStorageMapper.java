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

import java.util.LinkedList;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordUserCredentialModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPOperationManager;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPOperationManager.LdapOperation;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPOperationDecorator;
import org.keycloak.storage.ldap.mappers.PasswordUpdateCallback;
import org.keycloak.storage.ldap.mappers.TxAwareLDAPUserModelDelegate;

/**
 * Mapper specific to LDAP supporting password policy as per IETF behera draft
 * (https://tools.ietf.org/id/draft-behera-ldap-password-policy-10.html), such as OpenLDAP.
 * <br/>
 * When configured a password policy request control is set in LDAP context before binding for authentication and operations.
 * <ul>
 * <li>If authentication fails and the password policy response control indicates that password is expired user is allowed to continue
 * but an update password required action is requested.</li>
 * <li>On password update exception the generic password quality message is returned if response control indicates the reason.
 * Be aware that in OpenLDAP binding as root DN to update a password bypasses all quality checks.</li>
 * </ul>
 * 
 * @author <a href="mailto:da.gaffuri@gmail.com">Daniele Gaffuri</a>
 */
public class PasswordPolicyControlStorageMapper extends AbstractLDAPStorageMapper implements PasswordUpdateCallback {

    private static final Logger logger = Logger.getLogger(PasswordPolicyControlStorageMapper.class);
    
    private class PassswordPolicyDecorator implements LDAPOperationDecorator {

 		@Override
		public List<Control> beforeLDAPContextCreation(final LdapOperation ldapOperation) {
			return getAuthenticationControls();
		}

		@Override
        public void beforeLDAPOperation(final LdapContext ldapContext, final LDAPOperationManager.LdapOperation ldapOperation) throws NamingException {
            logger.debug("Applying PasswordPolicy OID before update password");
            ldapContext.setRequestControls(new Control[] { getPasswordPolicyControl() });
        }
    }

    public PasswordPolicyControlStorageMapper(final ComponentModel mapperModel, final LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
        ldapProvider.setUpdater(this);
    }

    @Override
    public void beforeLDAPQuery(final LDAPQuery query) {
    }

    @Override
    public LDAPOperationDecorator beforePasswordUpdate(final UserModel user, final LDAPObject ldapUser, final PasswordUserCredentialModel password) {
        // Not apply policies if password is reset by admin (not by user himself)
        if (password.isAdminRequest()) {
            return null;
        }

        return new PassswordPolicyDecorator();
    }

    @Override
    public void passwordUpdated(final UserModel user, final LDAPObject ldapUser, final PasswordUserCredentialModel password) {
    }

    @Override
    public void passwordUpdateFailed(final UserModel user, final LDAPObject ldapUser, final PasswordUserCredentialModel password, final ModelException exception) {
        throw processFailedPasswordUpdateException(exception);
    }

    @Override
    public UserModel proxy(final LDAPObject ldapUser, final UserModel delegate, final RealmModel realm) {
        return new TxAwareLDAPUserModelDelegate(delegate, ldapProvider, ldapUser) {
		};
    }

    @Override
    public void onRegisterUserToLDAP(final LDAPObject ldapUser, final UserModel localUser, final RealmModel realm) {

    }

    @Override
    public void onImportUserFromLDAP(final LDAPObject ldapUser, final UserModel user, final RealmModel realm, final boolean isCreate) {

    }

    @Override
	public List<Control> getAuthenticationControls() {
    	List<Control> controls = new LinkedList<>(super.getAuthenticationControls());
		controls.add(getPasswordPolicyControl());
		return controls;
	}
    
	@Override
    public boolean onAuthenticationFailure(final LDAPObject ldapUser, final UserModel user, final AuthenticationException ldapException, final RealmModel realm) {
        PasswordPolicyResponseControl response = getResponseControl(ldapException);
        if (response != null && response.getError() != null) {
        	switch (response.getError()) {
        	case passwordExpired:
                // User needs to change his password. Allow him to login, but add UPDATE_PASSWORD required action
                if (!user.getRequiredActions().contains(UserModel.RequiredAction.UPDATE_PASSWORD.name())) {
                    user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                }
                return true;
        	case accountLocked:
                logger.warnf("Locked user '%s' attempt to login", user.getUsername());
                break;
            default:
            }
    	}

        return false;
    }

    protected ModelException processFailedPasswordUpdateException(final ModelException e) {
        if (e.getCause() == null) {
            return e;
        }
        PasswordPolicyResponseControl response = getResponseControl(e.getCause());
        if (response != null && response.getError() != null) {
	        switch (response.getError()) {
	        case insufficientPasswordQuality:
	        case passwordInHistory:
	        case passwordTooShort:
	        	// don't know configured limits, can't use more specific messages
	            ModelException me = new ModelException("invalidPasswordGenericMessage", e);
	        	return me;
	        default:
	        }
        }

        return e;
    }
    
    private PasswordPolicyResponseControl getResponseControl(final Throwable t) {
    	PasswordPolicyResponseControl response = null;
    	if (t instanceof NamingException) {
        	Object resolvedObj = ((NamingException) t).getResolvedObj();
        	if (resolvedObj instanceof LdapContext) {
                try {
                    response = PasswordPolicyResponseControl.getInstance(((LdapContext) resolvedObj));
                    if (logger.isDebugEnabled()) {
                        logger.debugf("PasswordPolicyResponseControl is [%s]", response);
                    }
                } catch (Exception e) {
                    if (logger.isDebugEnabled()) {
                        logger.debugf(e, "Error retrieving password control");
                    }
                }
        	}
        }
    	return response;
    }

    private Control getPasswordPolicyControl() {
    	return new BasicControl(PasswordPolicyResponseControl.OID);
    }

}
