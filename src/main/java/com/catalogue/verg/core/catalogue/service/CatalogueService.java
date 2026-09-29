package com.catalogue.verg.core.catalogue.service;

/** Verifies a login against the user-catalogue, the only place a password or PIN exists. */
public interface CatalogueService {

    /** The catalogue's userId for these credentials; 401 if rejected, 503 otherwise. Never log the password. */
    String verifyCredentials(String email, String password);

    /** Checks a PIN for the device's userId; 401 AUTH_INVALID_CREDENTIALS if rejected, else 503. */
    void verifyPin(String userId, String pin);
}
