/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreExtension;
import org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreExtension;
import org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreProvider;

import javax.net.ssl.SSLContext;
import java.security.Provider;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Service that manages the lifecycle of a HashiCorp Vault credential store.
 * Uses the legacy MSC Service pattern to support ServiceController.getService() calls
 * for cross-subsystem credential-reference integration.
 */
public class CredentialStoreService implements Service<CredentialStore> {
    
    /**
     * Initialization parameters for the credential store.
     */
    public static class InitializationParams {
        private final Map<String, String> attributes;
        private final CredentialStore.CredentialSourceProtectionParameter protectionParameter;
        private final Provider[] providers;
        private final SSLContext sslContext;

        public InitializationParams(Map<String, String> attributes,
                                    CredentialStore.CredentialSourceProtectionParameter protectionParameter,
                                    SSLContext sslContext,
                                    Provider[] providers) {
            this.attributes = attributes;
            this.sslContext = sslContext;
            this.protectionParameter = protectionParameter;
            this.providers = providers;
        }
        
        public Map<String, String> getAttributes() {
            return attributes;
        }

        public SSLContext getSSLContext() {
            return sslContext;
        }
        
        public CredentialStore.CredentialSourceProtectionParameter getProtectionParameter() {
            return protectionParameter;
        }
        
        public Provider[] getProviders() {
            return providers;
        }
    }
    
    private final Supplier<InitializationParams> initParamsSupplier;
    private final Consumer<CredentialStore> credentialStoreConsumer;
    private volatile CredentialStore credentialStore;
    
    /**
     * Creates a new credential store service.
     * 
     * @param initParamsSupplier supplier that provides the initialization parameters
     * @param credentialStoreConsumer consumer to handle the created CredentialStore (can be null)
     */
    public CredentialStoreService(Supplier<InitializationParams> initParamsSupplier, 
                                   Consumer<CredentialStore> credentialStoreConsumer) {
        this.initParamsSupplier = initParamsSupplier;
        this.credentialStoreConsumer = credentialStoreConsumer;
    }

    public CredentialStoreService(Supplier<InitializationParams> initParamsSupplier) {
        this(initParamsSupplier, null);
    }
    
    @Override
    public void start(StartContext context) throws StartException {
        try {
            InitializationParams params = initParamsSupplier.get();
            Provider provider = HashicorpVaultCredentialStoreProvider.getInstance();
            credentialStore = CredentialStore.getInstance("HashicorpVaultCredentialStore", provider);

            List<Class<? extends CredentialStoreExtension>> supportedTypes = credentialStore.getSupportedExtensionTypes();
            if (!supportedTypes.contains(HashicorpVaultCredentialStoreExtension.class)) {
                throw new StartException("Failed to create and initialize HC Vault CredentialStore.");
            }

            HashicorpVaultCredentialStoreExtension hashicorpVaultCredentialStoreExtension = credentialStore.getExtensionInstance(HashicorpVaultCredentialStoreExtension.class);

            hashicorpVaultCredentialStoreExtension.setSslContext(params.getSSLContext());

            credentialStore.initialize(
                params.getAttributes(),
                params.getProtectionParameter(),
                params.getProviders()
            );


            if (credentialStoreConsumer != null) {
                credentialStoreConsumer.accept(credentialStore);
            }
        } catch (Exception e) {
            throw new StartException("Failed to create and initialize CredentialStore: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void stop(StopContext context) {
        if (credentialStore != null) {
            try {
                credentialStore.flush();
            } catch (Exception e) {
                throw new RuntimeException("Failed to stop Credential store service");
            }
        }
        credentialStore = null;
    }
    
    @Override
    public CredentialStore getValue() throws IllegalStateException {
        if (credentialStore == null) {
            throw new IllegalStateException("CredentialStore service not started");
        }
        return credentialStore;
    }
}

