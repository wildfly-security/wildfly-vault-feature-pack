/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import java.io.IOException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Elytron authentication-context with {@code ssl-context} match-rules and mutual TLS to Vault (HTTPS listener requires client certificate).
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultHttpsMutualTlsAuthenticationContextIntegrationTestCase.ElytronSetup.class)
public class HashiCorpVaultHttpsMutualTlsAuthenticationContextIntegrationTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-mtls-store";
    private static final VaultHttpsElytronSetup.SetupNames NAMES = VaultHttpsElytronSetup.SetupNames.mutualTls();

    private static final VaultContainerHttps<?> VAULT;

    static {
        try {
            VAULT = new VaultContainerHttps<>("hashicorp/vault:1.21", true);
            VAULT.withVaultToken(VAULT_TOKEN).withInitCommand(
                    "secrets enable kv-v2",
                    "kv put secret/testing1 top_secret=password123"
            );
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-https-mtls-auth-context-test.jar");
    }

    /**
     * Adds a HashiCorp Vault credential store over HTTPS where Vault requires mutual TLS, using the matching Elytron
     * {@code authentication-context}, then removes it.
     * <p><b>Passes when:</b> both management operations ({@code add} and {@code remove} for the credential-store) complete
     * with {@code outcome=success} (no exception from {@link VaultHttpsElytronSetup#executeSuccess}).
     */
    @Test
    public void testCredentialStoreWithAuthenticationContextOverMutualTlsHttps(@ArquillianResource ManagementClient managementClient) {
        PathAddress storeAddress = PathAddress.pathAddress(PathElement.pathElement("subsystem", "hashicorp-vault"))
                .append("credential-store", CREDENTIAL_STORE_NAME);

        ModelNode add = Util.createAddOperation(storeAddress);
        add.get("host-address").set(VAULT.composeHttpsHostAddress());
        add.get("authentication-context").set(NAMES.authenticationContext);
        add.get("credential-reference", "clear-text").set(VAULT_TOKEN);

        VaultHttpsElytronSetup.executeSuccess(managementClient, add);

        ModelNode remove = Util.createRemoveOperation(storeAddress);
        remove.get("operation-headers", "allow-resource-service-restart").set(true);
        VaultHttpsElytronSetup.executeSuccess(managementClient, remove);
    }

    public static final class ElytronSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            if (!VAULT.isRunning()) {
                VAULT.start();
            }
            VaultHttpsElytronSetup.install(managementClient, VAULT, NAMES, true);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            VaultHttpsElytronSetup.tearDown(managementClient, NAMES, true);
            VAULT.stop();
        }
    }
}
