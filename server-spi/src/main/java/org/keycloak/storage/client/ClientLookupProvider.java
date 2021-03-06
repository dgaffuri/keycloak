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
package org.keycloak.storage.client;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Abstraction interface for lookoup of clients by id and clientId.  These methods required for participating in login flows.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface ClientLookupProvider {
    
    /**
     * Exact search for a client by its internal ID.
     * @param realm Realm to limit the search.
     * @param id Internal ID
     * @return Model of the client, or {@code null} if no client is found.
     */
    ClientModel getClientById(RealmModel realm, String id);

    /**
     * Exact search for a client by its internal ID.
     * @param realm Realm to limit the search.
     * @param id Internal ID
     * @return Model of the client, or {@code null} if no client is found.
     * @deprecated Use {@link #getClientById(org.keycloak.models.RealmModel, java.lang.String)} instead.
     */
    default ClientModel getClientById(String id, RealmModel realm) { return getClientById(realm, id); }

    /**
     * Exact search for a client by its public client identifier.
     * @param realm Realm to limit the search for clients.
     * @param clientId String that identifies the client to the external parties.
     *   Maps to {@code client_id} in OIDC or {@code entityID} in SAML.
     * @return Model of the client, or {@code null} if no client is found.
     */
    ClientModel getClientByClientId(RealmModel realm, String clientId);

    /**
     * Exact search for a client by its public client identifier.
     * @param realm Realm to limit the search.
     * @param clientId String that identifies the client to the external parties.
     *   Maps to {@code client_id} in OIDC or {@code entityID} in SAML.
     * @return Model of the client, or {@code null} if no client is found.
     * @deprecated Use {@link #getClientByClientId(org.keycloak.models.RealmModel, java.lang.String)} instead.
     */
    default ClientModel getClientByClientId(String clientId, RealmModel realm) { return getClientByClientId(realm, clientId); }

    /**
     * Case-insensitive search for clients that contain the given string in their public client identifier.
     * @param realm Realm to limit the search for clients.
     * @param clientId Searched substring of the public client
     *   identifier ({@code client_id} in OIDC or {@code entityID} in SAML.)
     * @param firstResult First result to return. Ignored if negative or {@code null}.
     * @param maxResults Maximum number of results to return. Ignored if negative or {@code null}.
     * @return List of ClientModel or an empty list if no client is found.
     * @deprecated Use {@link #searchClientsByClientIdStream(org.keycloak.models.RealmModel, java.lang.String, java.lang.Integer, java.lang.Integer)} instead.
     */
    @Deprecated
    default List<ClientModel> searchClientsByClientId(String clientId, Integer firstResult, Integer maxResults, RealmModel realm) {
        return searchClientsByClientIdStream(realm, clientId, firstResult, maxResults).collect(Collectors.toList());
    }

    /**
     * Case-insensitive search for clients that contain the given string in their public client identifier.
     * @param realm Realm to limit the search for clients.
     * @param clientId Searched substring of the public client
     *   identifier ({@code client_id} in OIDC or {@code entityID} in SAML.)
     * @param firstResult First result to return. Ignored if negative or {@code null}.
     * @param maxResults Maximum number of results to return. Ignored if negative or {@code null}.
     * @return Stream of ClientModel or an empty stream if no client is found. Never returns {@code null}.
     */
    Stream<ClientModel> searchClientsByClientIdStream(RealmModel realm, String clientId, Integer firstResult, Integer maxResults);
}
