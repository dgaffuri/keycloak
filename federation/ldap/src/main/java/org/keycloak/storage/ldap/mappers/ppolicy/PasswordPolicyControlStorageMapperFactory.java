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

import java.util.ArrayList;
import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;

/**
 * @author <a href="mailto:da.gaffuri@gmail.com">Daniele Gaffuri</a>
 */
public class PasswordPolicyControlStorageMapperFactory extends AbstractLDAPStorageMapperFactory {

    public static final String PROVIDER_ID = LDAPConstants.PASSWORD_POLICY_CONTROL_MAPPER;
    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public String getHelpText() {
        return "Mapper specific to LDAP supporting password policy such as OpenLDAP. " +
               "When configured it's able to manage expired passwords at login time and show a more meaningful message for quality errors at password update time.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(final ComponentModel mapperModel, final LDAPStorageProvider federationProvider) {
        return new PasswordPolicyControlStorageMapper(mapperModel, federationProvider);
    }
}
