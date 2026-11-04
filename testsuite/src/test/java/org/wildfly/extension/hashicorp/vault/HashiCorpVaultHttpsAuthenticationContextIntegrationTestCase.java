/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

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
 * Provisions Elytron authentication-context with an {@code ssl-context} match-rule (trust only) and adds a HashiCorp Vault credential store over HTTPS.
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultHttpsAuthenticationContextIntegrationTestCase.ElytronSetup.class)
public class HashiCorpVaultHttpsAuthenticationContextIntegrationTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-https-store";
    private static final VaultHttpsElytronSetup.SetupNames NAMES = VaultHttpsElytronSetup.SetupNames.oneWayHttps();

    private static VaultContainerHttps<?> vault;

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-https-auth-context-test.jar");
    }

    /**
     * Adds a HashiCorp Vault credential store that talks to Vault over HTTPS using an Elytron {@code authentication-context}
     * (server trusts Vault TLS only), then removes it.
     * <p><b>Passes when:</b> both management operations ({@code add} and {@code remove} for the credential-store) complete
     * with {@code outcome=success} (no exception from {@link VaultHttpsElytronSetup#executeSuccess}).
     */
    @Test
    public void testCredentialStoreWithAuthenticationContextOverHttps(@ArquillianResource ManagementClient managementClient) {
        PathAddress storeAddress = PathAddress.pathAddress(PathElement.pathElement("subsystem", "hashicorp-vault"))
                .append("credential-store", CREDENTIAL_STORE_NAME);

        ModelNode add = Util.createAddOperation(storeAddress);
        add.get("host-address").set(vault.composeHttpsHostAddress());
        add.get("client-ssl-context").set(NAMES.sslContext);
        add.get("credential-reference", "clear-text").set(VAULT_TOKEN);

        VaultHttpsElytronSetup.executeSuccess(managementClient, add);

        ModelNode remove = Util.createRemoveOperation(storeAddress);
        remove.get("operation-headers", "allow-resource-service-restart").set(true);
        VaultHttpsElytronSetup.executeSuccess(managementClient, remove);
    }

    public static final class ElytronSetup implements ServerSetupTask {

        private boolean elytronSetupStarted;

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            VaultTestSupport.assumeDockerAvailable();
            vault = new VaultContainerHttps<>(VaultImages.VAULT, false);
            vault.withVaultToken(VAULT_TOKEN).withInitCommand(
                    "secrets enable kv-v2",
                    "kv put secret/testing1 top_secret=password123"
            );
            vault.start();
            elytronSetupStarted = true;
            VaultHttpsElytronSetup.install(managementClient, vault, NAMES, false);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            try {
                if (elytronSetupStarted) {
                    VaultHttpsElytronSetup.tearDown(managementClient, NAMES, false);
                    elytronSetupStarted = false;
                }
            } finally {
                if (vault != null) {
                    vault.close();
                    vault = null;
                }
            }
        }
    }
}
