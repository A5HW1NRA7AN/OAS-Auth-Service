# Keycloak with the OAS catalogue password authenticator baked in.
#
# The jar is built separately (./authenticator) and copied in here.
# `kc.sh build` is what makes Keycloak actually discover a new provider — dropping a jar
# into /opt/keycloak/providers/ without re-running the build leaves the provider invisible,
# with no error message anywhere.
#
# Build context is the repo root (see docker-compose.yml), so that this can reach the
# sibling module's target/ directory.

FROM quay.io/keycloak/keycloak:26.7

COPY keycloak/authenticator/target/keycloak-catalogue-authenticator.jar \
     /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
