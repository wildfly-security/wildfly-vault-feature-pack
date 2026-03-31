/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.dmr.ModelNode;

/**
 * Elytron resources + trust/client keystores for HTTPS (and optional mutual TLS) to HashiCorp Vault.
 */
public final class VaultHttpsElytronSetup {

    private static final char[] JKS_PASSWORD = "changeit".toCharArray();

    private VaultHttpsElytronSetup() {
    }

    /**
     * Prepares the WildFly server so outbound HTTPS to the given Vault container can use Elytron TLS configuration.
     * <p>
     * Writes a trust JKS under {@code jboss.server.config.dir} from Vault's HTTPS CA PEM, then adds Elytron
     * {@code key-store} (trust), {@code trust-manager}, and {@code client-ssl-context}. If {@code mutualTls} is
     * {@code true}, also copies the client keystore from the container, adds client {@code key-store},
     * {@code key-manager}, and builds an {@code client-ssl-context} with both key- and trust-managers.
     * Finally adds an {@code authentication-context} with a {@code match-host} rule for {@code 127.0.0.1} bound to
     * that SSL context.
     * <p>
     * Each management operation must succeed ({@link #executeSuccess}); otherwise an {@link AssertionError} is thrown.
     * I/O or keystore failures propagate as {@link Exception}.
     *
     * @param client     management client for the running WildFly instance ({@code jboss.home} must be set)
     * @param vault      Testcontainers Vault with HTTPS (and optional mTLS) material from {@link VaultContainerHttps}
     * @param names      Elytron resource names and on-disk JKS file names for this scenario
     * @param mutualTls  if {@code true}, configure client certificate for mutual TLS; if {@code false}, trust-only TLS
     * @throws Exception if filesystem or keystore operations fail
     */
    public static void install(ManagementClient client, VaultContainerHttps<?> vault, SetupNames names, boolean mutualTls) throws Exception {
        Path jbossHome = Path.of(System.getProperty("jboss.home"));
        Path configDir = jbossHome.resolve("standalone").resolve("configuration");
        Files.createDirectories(configDir);

        Path trustJks = configDir.resolve(names.trustJksFileName);
        writeTrustStoreFromPem(vault.getHttpsTrustFile(), trustJks, JKS_PASSWORD);

        PathAddress elytron = PathAddress.pathAddress("subsystem", "elytron");

        ModelNode addTrustKs = Util.createAddOperation(elytron.append("key-store", names.trustKeyStore));
        addTrustKs.get("type").set("JKS");
        addTrustKs.get("path").set(names.trustJksFileName);
        addTrustKs.get("relative-to").set("jboss.server.config.dir");
        addTrustKs.get("credential-reference", "clear-text").set(new String(JKS_PASSWORD));
        executeSuccess(client, addTrustKs);

        ModelNode addTm = Util.createAddOperation(elytron.append("trust-manager", names.trustManager));
        addTm.get("key-store").set(names.trustKeyStore);
        executeSuccess(client, addTm);

        if (mutualTls) {
            Path clientJks = configDir.resolve(names.clientJksFileName);
            Files.copy(vault.getClientKeyStorePath(), clientJks, StandardCopyOption.REPLACE_EXISTING);

            ModelNode addClientKs = Util.createAddOperation(elytron.append("key-store", names.clientKeyStore));
            addClientKs.get("type").set("JKS");
            addClientKs.get("path").set(names.clientJksFileName);
            addClientKs.get("relative-to").set("jboss.server.config.dir");
            // Password must match smallrye-generated client JKS (see VaultContainerHttps#getClientKeyStorePassword), not trust-store JKS_PASSWORD
            addClientKs.get("credential-reference", "clear-text").set(vault.getClientKeyStorePassword());
            executeSuccess(client, addClientKs);

            ModelNode addKm = Util.createAddOperation(elytron.append("key-manager", names.keyManager));
            addKm.get("key-store").set(names.clientKeyStore);
            addKm.get("credential-reference", "clear-text").set(vault.getClientKeyStorePassword());
            addKm.get("alias-filter").set(VaultContainerHttps.getClientCertificateKeyAlias());
            executeSuccess(client, addKm);

            ModelNode addSsl = Util.createAddOperation(elytron.append("client-ssl-context", names.sslContext));
            addSsl.get("key-manager").set(names.keyManager);
            addSsl.get("trust-manager").set(names.trustManager);
            addSsl.get("cipher-suite-filter").set("DEFAULT");
            executeSuccess(client, addSsl);
        } else {
            ModelNode addSsl = Util.createAddOperation(elytron.append("client-ssl-context", names.sslContext));
            addSsl.get("trust-manager").set(names.trustManager);
            addSsl.get("cipher-suite-filter").set("DEFAULT");
            executeSuccess(client, addSsl);
        }

        ModelNode addAuthCtx = Util.createAddOperation(elytron.append("authentication-context", names.authenticationContext));
        ModelNode rule = new ModelNode();
        rule.get("match-host").set("127.0.0.1");
        rule.get("ssl-context").set(names.sslContext);
        addAuthCtx.get("match-rules").add(rule);
        executeSuccess(client, addAuthCtx);
    }

    public static void tearDown(ManagementClient client, SetupNames names, boolean mutualTls) throws Exception {
        PathAddress elytron = PathAddress.pathAddress("subsystem", "elytron");
        List<ModelNode> ops = new ArrayList<>();
        ops.add(Util.createRemoveOperation(elytron.append("authentication-context", names.authenticationContext)));
        ops.add(Util.createRemoveOperation(elytron.append("client-ssl-context", names.sslContext)));
        if (mutualTls) {
            ops.add(Util.createRemoveOperation(elytron.append("key-manager", names.keyManager)));
            ops.add(Util.createRemoveOperation(elytron.append("key-store", names.clientKeyStore)));
        }
        ops.add(Util.createRemoveOperation(elytron.append("trust-manager", names.trustManager)));
        ops.add(Util.createRemoveOperation(elytron.append("key-store", names.trustKeyStore)));
        for (ModelNode op : ops) {
            op.get("operation-headers", "allow-resource-service-restart").set(true);
            try {
                client.getControllerClient().execute(op);
            } catch (Exception ignored) {
                // ignore
            }
        }
    }

    public static void executeSuccess(ManagementClient client, ModelNode operation) {
        final ModelNode response;
        try {
            response = client.getControllerClient().execute(operation);
        } catch (IOException e) {
            throw new AssertionError("Management request failed: " + operation, e);
        }
        if (!SUCCESS.equals(response.get(OUTCOME).asString())) {
            throw new AssertionError("Operation should succeed: " + operation + " -> " + response
                    + (response.hasDefined(FAILURE_DESCRIPTION) ? " / " + response.get(FAILURE_DESCRIPTION) : ""));
        }
    }

    /**
     * Resource and file names for one scenario (one-way HTTPS vs mTLS).
     */
    public static final class SetupNames {
        final String trustJksFileName;
        final String trustKeyStore;
        final String trustManager;
        final String sslContext;
        final String authenticationContext;
        final String clientJksFileName;
        final String clientKeyStore;
        final String keyManager;

        private SetupNames(String trustJksFileName, String trustKeyStore, String trustManager, String sslContext,
                String authenticationContext,
                String clientJksFileName, String clientKeyStore, String keyManager) {
            this.trustJksFileName = trustJksFileName;
            this.trustKeyStore = trustKeyStore;
            this.trustManager = trustManager;
            this.sslContext = sslContext;
            this.authenticationContext = authenticationContext;
            this.clientJksFileName = clientJksFileName;
            this.clientKeyStore = clientKeyStore;
            this.keyManager = keyManager;
        }

        public static SetupNames oneWayHttps() {
            return new SetupNames(
                    "vault-https-trust.jks",
                    "vault-https-trust-ks",
                    "vault-https-trust-tm",
                    "vault-https-ssl",
                    "vault-auth-context",
                    "",
                    "",
                    "");
        }

        public static SetupNames mutualTls() {
            return new SetupNames(
                    "vault-mtls-trust.jks",
                    "vault-mtls-trust-ks",
                    "vault-mtls-trust-tm",
                    "vault-mtls-ssl",
                    "vault-mtls-auth-context",
                    "vault-mtls-client.jks",
                    "vault-mtls-client-ks",
                    "vault-mtls-client-km");
        }
    }

    private static void writeTrustStoreFromPem(Path pemFile, Path jksFile, char[] password) throws Exception {
        String pem = Files.readString(pemFile, StandardCharsets.UTF_8);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> parsed = cf.generateCertificates(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        List<Certificate> certs = new ArrayList<>(parsed);
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("No certificates in PEM: " + pemFile);
        }
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, password);
        for (int i = 0; i < certs.size(); i++) {
            ks.setCertificateEntry("vault-ca-" + i, certs.get(i));
        }
        try (OutputStream os = Files.newOutputStream(jksFile)) {
            ks.store(os, password);
        }
    }
}
