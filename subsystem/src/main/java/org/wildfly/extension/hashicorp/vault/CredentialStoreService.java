/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.wildfly.extension.hashicorp.vault._private.HashiCorpVaultLogger;
import org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.VaultCredentialStoreDoohickey;

import org.jboss.msc.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;

import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

/**
 * MSC service that manages the lifecycle of a HashiCorp Vault credential store.
 *
 * <p>Works in conjunction with {@link VaultCredentialStoreDoohickey}: if the early-access API
 * path has already initialized the store before this service starts, {@code start()} reuses that
 * instance. Otherwise it builds the store from the wired MSC suppliers and publishes the result
 * through the doohickey so both access paths see the same object. On stop the doohickey is reset
 * so the next service start rebuilds a fresh instance.</p>
 */
public class CredentialStoreService implements Service, Supplier<CredentialStore> {

    private final VaultCredentialStoreDoohickey doohickey;
    private final Consumer<CredentialStore> storeConsumer;

    /**
     * Optional injected SSLContext supplier for HTTPS connections to Vault.
     * Populated by MSC when a {@code client-ssl-context} attribute is configured.
     */
    private volatile Supplier<SSLContext> clientSslContextSupplier;

    /**
     * Optional injected credential-source supplier for the Vault token.
     * Populated by MSC when a {@code credential-reference} attribute is configured.
     * The add handler wires this via {@code CredentialReference.getCredentialSourceSupplier}.
     */
    private volatile ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier;

    private volatile CredentialStore credentialStore;

    /**
     * Creates a new service backed by the given doohickey and value consumer.
     *
     * @param doohickey the doohickey that coordinates early-access and service-path initialization
     * @param storeConsumer consumer to receive the initialized credential store
     */
    CredentialStoreService(VaultCredentialStoreDoohickey doohickey, Consumer<CredentialStore> storeConsumer) {
        this.doohickey = doohickey;
        this.storeConsumer = storeConsumer;
    }

    /**
     * Sets the SSLContext supplier wired by the add handler when a {@code client-ssl-context} attribute is configured.
     */
    void setClientSslContextSupplier(Supplier<SSLContext> supplier) {
        this.clientSslContextSupplier = supplier;
    }

    /**
     * Sets the credential-source supplier wired by the add handler for the Vault token.
     * Called from {@code performRuntime} after the MSC service builder has been configured.
     */
    void setCredentialSourceSupplier(ExceptionSupplier<CredentialSource, Exception> supplier) {
        this.credentialSourceSupplier = supplier;
    }

    @Override
    public void start(StartContext context) throws StartException {
        credentialStore = doohickey.getForService(() -> {
            // Service-path builder: called only when the early-access path has not already run.
            SSLContext sslContext = clientSslContextSupplier != null ? clientSslContextSupplier.get() : null;

            String token = null;
            if (credentialSourceSupplier != null) {
                try {
                    CredentialSource cs = credentialSourceSupplier.get();
                    if (cs != null) {
                        PasswordCredential pc = cs.getCredential(PasswordCredential.class);
                        if (pc != null) {
                            ClearPassword cp = pc.getPassword(ClearPassword.class);
                            if (cp != null) {
                                token = new String(cp.getPassword());
                            }
                        }
                    }
                } catch (Exception e) {
                    throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreStartFailed(e);
                }
            }

            try {
                return VaultCredentialStoreDoohickey.buildCredentialStore(
                        doohickey.getHostAddress(), doohickey.getNamespace(),
                        doohickey.isSupportLegacyFormat(), token, sslContext);
            } catch (Exception e) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreStartFailed(e);
            }
        });
        if (storeConsumer != null) {
            storeConsumer.accept(credentialStore);
        }
    }

    @Override
    public void stop(StopContext context) {
        if (storeConsumer != null) {
            storeConsumer.accept(null);
        }
        if (credentialStore != null) {
            try {
                credentialStore.flush();
            } catch (Exception e) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreStopFailed(e);
            }
        }
        credentialStore = null;
        doohickey.reset();
    }

    @Override
    public CredentialStore get() {
        return getValue();
    }

    public CredentialStore getValue() throws IllegalStateException {
        if (credentialStore == null) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreServiceNotStarted();
        }
        return credentialStore;
    }
}
