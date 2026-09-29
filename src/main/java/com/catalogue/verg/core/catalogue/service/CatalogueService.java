package com.catalogue.verg.core.catalogue.service;

/** Verifies a login against the user-catalogue, the only place a password or PIN exists. */
public interface CatalogueService {

    /**
     * @param email    the login identifier; the catalogue has no username column
     * @param password plaintext, never logged or stored
     * @return the catalogue's userId, non-blank — never the submitted email
     * @throws com.catalogue.verg.core.exception.CustomException 401 when the catalogue rejects the
     *         credentials, 503 for anything else. Fails closed: no return value means "not verified".
     */
    String verifyCredentials(String email, String password);

    /** Checks a PIN for the device's userId; 401 AUTH_INVALID_CREDENTIALS if rejected, else 503. */
    void verifyPin(String userId, String pin);
}
