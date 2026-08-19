package com.catalogue.verg.core.catalogue.service;

/** Verifies a login against the user-catalogue, the only place a password exists. */
public interface CatalogueService {

    /**
     * @param username whatever the user typed; the catalogue resolves it
     * @param password plaintext, never logged or stored
     * @return the catalogue's userId, always non-blank — never the submitted username
     * @throws com.catalogue.verg.core.exception.CustomException 401 on {@code valid:false}, 503 for
     *         anything else (unreachable, non-2xx, unparseable, or no userId). Fails closed: there is
     *         no return value meaning "not verified".
     */
    String verifyCredentials(String username, String password);
}
