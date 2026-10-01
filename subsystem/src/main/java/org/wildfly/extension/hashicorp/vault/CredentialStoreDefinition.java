/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.wildfly.extension.hashicorp.vault._private.HashiCorpVaultLogger;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ReloadRequiredWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleOperationDefinition;
import org.jboss.as.controller.SimpleOperationDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.descriptions.NonResolvingResourceDescriptionResolver;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.jboss.msc.service.StartException;
import org.wildfly.common.function.ExceptionFunction;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.extension.elytron.DoohickeySimultaneity;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreExtension;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreExtension;
import org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreProvider;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;

import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_STORE_CAPABILITY;

/**
 * Resource definition for credential stores backed by HashiCorp Vault.
 *
 */
public class CredentialStoreDefinition extends SimpleResourceDefinition {

    static final String HOST_ADDRESS = "host-address";
    static final String NAMESPACE = "namespace";
    static final String CLIENT_SSL_CONTEXT = "client-ssl-context";

    /** Elytron capability name for client-ssl-context (used for outbound TLS). */
    private static final String CLIENT_SSL_CONTEXT_CAPABILITY = "org.wildfly.security.client-ssl-context";

    /**
     * Early-access runtime API capability name for the client-ssl-context resource
     * (provided by WildFly Core's elytron subsystem). Used to obtain the SSLContext
     * before the client-ssl-context service has started.
     */
    private static final String CLIENT_SSL_CONTEXT_API_CAPABILITY = "org.wildfly.security.client-ssl-context-api";

    protected static final SimpleAttributeDefinition HOST_NAME_DEF =
            new SimpleAttributeDefinitionBuilder(HOST_ADDRESS, ModelType.STRING)
                    .setRequired(true)
                    .setAllowExpression(true)
                    .setXmlName(HOST_ADDRESS)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setStability(Stability.DEFAULT)
                    .build();

    protected static final SimpleAttributeDefinition NAMESPACE_DEF =
            new SimpleAttributeDefinitionBuilder(NAMESPACE, ModelType.STRING)
                    .setRequired(false)
                    .setAllowExpression(true)
                    .setXmlName(NAMESPACE)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setStability(Stability.DEFAULT)
                    .build();

    /**
     * Dummy attribute definition used only by the legacy schema parsers to recognise and reject
     * the old 'authentication-context' XML attribute with a helpful error message.
     * This attribute is NOT registered in the management model.
     */
    static final SimpleAttributeDefinition AUTHENTICATION_CONTEXT_LEGACY_DEF =
            new SimpleAttributeDefinitionBuilder("authentication-context", ModelType.STRING)
                    .setRequired(false)
                    .build();

    protected static final SimpleAttributeDefinition CLIENT_SSL_CONTEXT_DEF =
            new SimpleAttributeDefinitionBuilder(CLIENT_SSL_CONTEXT, ModelType.STRING)
                    .setRequired(false)
                    .setAllowExpression(false)
                    .setXmlName(CLIENT_SSL_CONTEXT)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setStability(Stability.DEFAULT)
                    .setCapabilityReference(CLIENT_SSL_CONTEXT_CAPABILITY, CREDENTIAL_STORE_CAPABILITY)
                    .build();

    static final RuntimeCapability<Void> CREDENTIAL_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CREDENTIAL_STORE_CAPABILITY, true, CredentialStore.class)
            .build();

    /**
     * Subsystem-private capability name. Only HashiCorp Vault credential stores advertise this capability,
     * which prevents {@link VaultExpressionResolver} from accidentally resolving expressions against
     * non-Vault credential stores registered under the generic Elytron capability.
     */
    static final String HASHICORP_VAULT_CREDENTIAL_STORE_CAPABILITY =
            "org.wildfly.extension.hashicorp-vault.credential-store";

    static final RuntimeCapability<Void> HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY =
            RuntimeCapability.Builder.of(HASHICORP_VAULT_CREDENTIAL_STORE_CAPABILITY, true, CredentialStore.class)
            .build();

    /**
     * Early-access runtime API capability name for the Vault credential store. Registering under this
     * name (alongside the service capability) allows {@link VaultExpressionResolver} and
     * {@link CredentialReference#getCredentialSource} to initialize the store on demand during
     * {@code Stage.RUNTIME} before its MSC service has started.
     *
     * <p>The value type is
     * {@code ExceptionFunction<OperationContext, CredentialStore, OperationFailedException>} —
     * the same contract as Elytron's {@code credential-store-api} capability, so
     * {@link CredentialReference#getCredentialSource} can retrieve a Vault token from a Vault
     * credential-reference without any special-casing.</p>
     */
    static final String VAULT_CREDENTIAL_STORE_API_CAPABILITY =
            "org.wildfly.security.credential-store-api";

    static final ObjectTypeAttributeDefinition CREDENTIAL_REFERENCE =
            CredentialReference.getAttributeBuilder("credential-reference", "credential-reference", true)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setCapabilityReference(CREDENTIAL_STORE_CAPABILITY, CREDENTIAL_STORE_RUNTIME_CAPABILITY)
                    .setStability(Stability.DEFAULT)
                    .setRequired(false)
                    .build();

    public static final Collection<AttributeDefinition> ATTRIBUTES = List.of(HOST_NAME_DEF, NAMESPACE_DEF,
            CLIENT_SSL_CONTEXT_DEF, CREDENTIAL_REFERENCE);

    static final StandardResourceDescriptionResolver OPERATION_RESOLVER =
            new StandardResourceDescriptionResolver("credential-store.operations",
                    "org.wildfly.extension.hashicorp.vault.LocalDescriptions",
                    CredentialStoreDefinition.class.getClassLoader());

    static final SimpleAttributeDefinition ALIAS = new SimpleAttributeDefinitionBuilder("alias", ModelType.STRING, false)
            .setMinSize(1)
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition SECRET_VALUE = new SimpleAttributeDefinitionBuilder("secret-value", ModelType.STRING, false)
            .setMinSize(0)
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder("path", ModelType.STRING, true)
            .setMinSize(0)  // Allow empty string to list all aliases
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition RECURSIVE = new SimpleAttributeDefinitionBuilder("recursive", ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition RECURSIVE_DEPTH = new SimpleAttributeDefinitionBuilder("recursive-depth", ModelType.INT, true)
            .setDefaultValue(new ModelNode(100))
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition MAX_NUMBER_OF_ALIASES = new SimpleAttributeDefinitionBuilder("max-number-of-aliases", ModelType.INT, true)
            .setDefaultValue(new ModelNode(10000))
            .setStability(Stability.DEFAULT)
            .build();

    private static final SimpleOperationDefinition READ_ALIASES = new SimpleOperationDefinitionBuilder("read-aliases", OPERATION_RESOLVER)
            .setParameters(PATH, RECURSIVE, RECURSIVE_DEPTH, MAX_NUMBER_OF_ALIASES)
            .setRuntimeOnly()
            .setReadOnly()
            .setStability(Stability.DEFAULT)
            .build();

    private static final SimpleOperationDefinition ADD_ALIAS = new SimpleOperationDefinitionBuilder("add-alias", OPERATION_RESOLVER)
            .setParameters(ALIAS, SECRET_VALUE)
            .setRuntimeOnly()
            .setStability(Stability.DEFAULT)
            .build();

    private static final SimpleOperationDefinition REMOVE_ALIAS = new SimpleOperationDefinitionBuilder("remove-alias", OPERATION_RESOLVER)
            .setParameters(ALIAS)
            .setRuntimeOnly()
            .setStability(Stability.DEFAULT)
            .build();

    public CredentialStoreDefinition() {
        super(new Parameters(PathElement.pathElement("credential-store", PathElement.WILDCARD_VALUE), NonResolvingResourceDescriptionResolver.INSTANCE)
                .setAddHandler(ADD_HANDLER)
                .setRemoveHandler(REMOVE_HANDLER)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setCapabilities(CREDENTIAL_STORE_RUNTIME_CAPABILITY, HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY));
    }

    @Override
    public Stability getStability() {
        return Stability.DEFAULT;
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition attr : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(attr, null, new ReloadRequiredWriteAttributeHandler(attr));
        }
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);

        resourceRegistration.registerOperationHandler(READ_ALIASES, new RuntimeOperationHandler(this::readAliasesOperation));
        resourceRegistration.registerOperationHandler(ADD_ALIAS, new RuntimeOperationHandler(this::addAliasOperation));
        resourceRegistration.registerOperationHandler(REMOVE_ALIAS, new RuntimeOperationHandler(this::removeAliasOperation));
    }

    private static AbstractAddStepHandler ADD_HANDLER = new AbstractAddStepHandler() {

        @Override
        protected void populateModel(ModelNode operation, ModelNode model) throws OperationFailedException {
            for (AttributeDefinition attr : ATTRIBUTES) {
                attr.validateAndSet(operation, model);
            }
        }

        @Override
        protected void recordCapabilitiesAndRequirements(OperationContext context, ModelNode operation, Resource resource)
                throws OperationFailedException {
            super.recordCapabilitiesAndRequirements(context, operation, resource);

            if (requiresRuntime(context)) {
                // Register the doohickey as a runtime API capability so that Stage.RUNTIME expression
                // resolution and CredentialReference.getCredentialSource() can initialize the store
                // on demand before its MSC service starts.
                VaultCredentialStoreDoohickey doohickey =
                        new VaultCredentialStoreDoohickey(context.getCurrentAddress());
                context.registerCapability(RuntimeCapability.Builder
                        .<ExceptionFunction<OperationContext, CredentialStore, OperationFailedException>>
                                of(VAULT_CREDENTIAL_STORE_API_CAPABILITY, true, doohickey)
                        .build()
                        .fromBaseCapability(context.getCurrentAddressValue()));
            }
        }

        @Override
        protected void rollbackRuntime(OperationContext context, ModelNode operation, Resource resource) {
            try {
                CredentialReference.rollbackCredentialStoreUpdate(CREDENTIAL_REFERENCE, context, resource);
            } catch (Exception e) {
                HashiCorpVaultLogger.ROOT_LOGGER.credentialReferenceRollbackFailed(e);
            }
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            final String name = context.getCurrentAddressValue();

            // Retrieve the doohickey that was registered in recordCapabilitiesAndRequirements.
            @SuppressWarnings("unchecked")
            ExceptionFunction<OperationContext, CredentialStore, OperationFailedException> runtimeApi =
                    context.getCapabilityRuntimeAPI(VAULT_CREDENTIAL_STORE_API_CAPABILITY, name, ExceptionFunction.class);
            VaultCredentialStoreDoohickey doohickey = (VaultCredentialStoreDoohickey) runtimeApi;

            // Resolve and cache model attributes into the doohickey for both access paths.
            doohickey.resolveRuntime(context);

            final ServiceName serviceName = CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);

            CredentialStoreService service = new CredentialStoreService(doohickey);

            ServiceBuilder<CredentialStore> serviceBuilder =
                    context.getServiceTarget().addService(serviceName, service);

            // Also register the service under the subsystem-private capability so that
            // VaultExpressionResolver can resolve ${HC_VAULT::...} expressions without
            // accidentally targeting a non-Vault credential store.
            ServiceName privateServiceName = HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
            serviceBuilder.addAliases(privateServiceName);

            // Wire the real MSC service dependency for the credential-reference so that
            // service restart properly re-evaluates the credential source. Also capture the
            // supplier so the service-path builder can resolve the token without a context.
            ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier =
                    CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);
            if (credentialSourceSupplier != null) {
                service.setCredentialSourceSupplier(credentialSourceSupplier);
            }

            // Wire the client-ssl-context service dependency if configured.
            if (CLIENT_SSL_CONTEXT_DEF.resolveModelAttribute(context, model).isDefined()) {
                String clientSslContextName = CLIENT_SSL_CONTEXT_DEF.resolveModelAttribute(context, model).asString();
                String sslCapability = RuntimeCapability.buildDynamicCapabilityName(CLIENT_SSL_CONTEXT_CAPABILITY, clientSslContextName);
                serviceBuilder.addDependency(
                        context.getCapabilityServiceName(sslCapability, SSLContext.class),
                        SSLContext.class,
                        service.getClientSslContextInjector());
            }

            serviceBuilder.install();
        }
    };

    private static AbstractRemoveStepHandler REMOVE_HANDLER = new AbstractRemoveStepHandler() {

        @Override
        protected void recordCapabilitiesAndRequirements(OperationContext context, ModelNode operation, Resource resource)
                throws OperationFailedException {
            super.recordCapabilitiesAndRequirements(context, operation, resource);
            if (requiresRuntime(context)) {
                // Deregister the API capability to prevent WFLYCTL0436 if the same resource name is added again.
                context.deregisterCapability(
                        RuntimeCapability.buildDynamicCapabilityName(
                                VAULT_CREDENTIAL_STORE_API_CAPABILITY, context.getCurrentAddressValue()));
            }
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            final String name = context.getCurrentAddressValue();
            ServiceName serviceName = CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
            context.removeService(serviceName);
        }
    };

    private static PasswordCredential createCredentialFromPassword(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    // -------------------------------------------------------------------------
    // VaultCredentialStoreDoohickey
    // -------------------------------------------------------------------------

    /**
     * Coordinates initialization of a HashiCorp Vault credential store across two access paths:
     *
     * <ol>
     *   <li><b>Early (API) path:</b> {@link #apply(OperationContext)} is called during
     *       {@code Stage.RUNTIME} expression resolution before the MSC service has started.
     *       It calls {@link #createImmediately} which builds and caches the store.</li>
     *   <li><b>Service path:</b> {@link CredentialStoreService#start} calls {@link #getForService}
     *       which reuses the cached instance if already built, or builds it now.</li>
     * </ol>
     *
     * <p>Exactly one initialization happens per resource lifecycle. The same {@link CredentialStore}
     * instance is returned by both access paths. All initialization is protected by the shared
     * {@link DoohickeySimultaneity} lock to prevent concurrent construction and detect cycles.</p>
     */
    static final class VaultCredentialStoreDoohickey
            implements ExceptionFunction<OperationContext, CredentialStore, OperationFailedException> {

        private final PathAddress resourceAddress;

        // Model-resolved attributes — populated by resolveRuntime() in Stage.MODEL→RUNTIME transition.
        private volatile String hostAddress;
        private volatile String namespace;
        private volatile String clientSslContextName;
        private volatile boolean supportLegacyFormat;
        /** The full resource model node, retained so that {@link #createImmediately} can call
         *  {@link CredentialReference#getCredentialSource(OperationContext, ObjectTypeAttributeDefinition, ModelNode)}
         *  with the correct parent model. */
        private volatile ModelNode resourceModel;
        private volatile boolean modelResolved = false;

        // The single canonical CredentialStore instance shared between both access paths.
        private volatile CredentialStore value;

        VaultCredentialStoreDoohickey(PathAddress resourceAddress) {
            this.resourceAddress = resourceAddress;
        }

        /**
         * Resolves and caches model attributes from the current operation context.
         * Called once from {@code performRuntime} in the add handler.
         */
        void resolveRuntime(OperationContext context) throws OperationFailedException {
            if (!modelResolved) {
                ModelNode model = context.readResourceFromRoot(resourceAddress).getModel();
                hostAddress = HOST_NAME_DEF.resolveModelAttribute(context, model).asString();
                namespace = NAMESPACE_DEF.resolveModelAttribute(context, model).asStringOrNull();
                clientSslContextName = CLIENT_SSL_CONTEXT_DEF.resolveModelAttribute(context, model).asStringOrNull();
                Stability stability = context.getStability();
                supportLegacyFormat = stability.enables(Stability.COMMUNITY);
                resourceModel = model;
                modelResolved = true;
            }
        }

        /**
         * Early-access path: invoked during {@code Stage.RUNTIME} before the MSC service starts.
         * Returns the cached store if already initialized; otherwise builds it under the
         * {@link DoohickeySimultaneity} lock.
         */
        @Override
        public CredentialStore apply(OperationContext foreignContext) throws OperationFailedException {
            CredentialStore current = value;
            if (current != null) {
                return current;
            }
            return DoohickeySimultaneity.withLock(resourceAddress, () -> {
                if (value == null) {
                    // Ensure model attributes are resolved even if called from a foreign context.
                    if (!modelResolved) {
                        resolveRuntime(foreignContext);
                    }
                    value = createImmediately(foreignContext);
                }
                return value;
            });
        }

        /**
         * Service path: invoked from {@link CredentialStoreService#start}. Reuses the cached
         * instance if the early path already ran; otherwise builds the store under the lock.
         */
        CredentialStore getForService(ExceptionSupplier<CredentialStore, StartException> builder) throws StartException {
            CredentialStore current = value;
            if (current != null) {
                return current;
            }
            try {
                return DoohickeySimultaneity.withLockForService(resourceAddress, () -> {
                    if (value == null) {
                        value = builder.get();
                    }
                    return value;
                });
            } catch (OperationFailedException e) {
                throw new StartException(e);
            }
        }

        /**
         * Returns the currently cached store, or {@code null} if not yet initialized.
         */
        CredentialStore cachedValue() {
            return value;
        }

        // ---- Accessors for the service-path builder in CredentialStoreService ----

        String getHostAddress() { return hostAddress; }
        String getNamespace()   { return namespace; }
        boolean isSupportLegacyFormat() { return supportLegacyFormat; }

        /**
         * Clears the cached store under the lock so that the next service start rebuilds it.
         * Called from {@link CredentialStoreService#stop}.
         */
        void reset() {
            DoohickeySimultaneity.withLockForReset(() -> value = null);
        }

        /**
         * Builds the credential store immediately using early-access paths for its dependencies
         * (SSL context via the {@code client-ssl-context-api} capability; credential source via
         * {@link CredentialReference#getCredentialSource}).
         */
        private CredentialStore createImmediately(OperationContext context) throws OperationFailedException {
            SSLContext sslContext = null;
            if (clientSslContextName != null) {
                @SuppressWarnings("unchecked")
                ExceptionFunction<OperationContext, SSLContext, OperationFailedException> sslApi =
                        context.getCapabilityRuntimeAPI(CLIENT_SSL_CONTEXT_API_CAPABILITY,
                                clientSslContextName, ExceptionFunction.class);
                sslContext = sslApi.apply(context);
            }

            String token = null;
            if (resourceModel != null && CREDENTIAL_REFERENCE.resolveModelAttribute(context, resourceModel).isDefined()) {
                try {
                    CredentialSource credentialSource = CredentialReference.getCredentialSource(context, CREDENTIAL_REFERENCE, resourceModel);
                    if (credentialSource != null) {
                        PasswordCredential passwordCredential = credentialSource.getCredential(PasswordCredential.class);
                        if (passwordCredential != null) {
                            ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
                            if (clearPassword != null) {
                                token = new String(clearPassword.getPassword());
                            }
                        }
                    }
                } catch (IOException e) {
                    throw HashiCorpVaultLogger.ROOT_LOGGER.failedToObtainCredentialFromReference(e);
                }
            }

            return buildCredentialStore(hostAddress, namespace, supportLegacyFormat, token, sslContext);
        }

        /**
         * Shared store construction logic used by both the early path ({@link #createImmediately})
         * and the service path ({@link CredentialStoreService#start}).
         */
        static CredentialStore buildCredentialStore(String hostAddress, String namespace,
                boolean supportLegacyFormat, String token, SSLContext sslContext)
                throws OperationFailedException {
            Map<String, String> attributes = new HashMap<>();
            attributes.put("host-address", hostAddress);
            if (namespace != null) {
                attributes.put("namespace", namespace);
            }
            attributes.put("support-legacy-alias-format", String.valueOf(supportLegacyFormat));

            CredentialStore.CredentialSourceProtectionParameter protectionParameter;
            if (token != null) {
                try {
                    protectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                            IdentityCredentials.NONE.withCredential(createCredentialFromPassword(token)));
                } catch (UnsupportedCredentialTypeException e) {
                    throw HashiCorpVaultLogger.ROOT_LOGGER.failedToInitializeHashiCorpVaultCredentialStore(e.getMessage(), e);
                }
            } else {
                protectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE);
            }

            Provider[] providers = new Provider[] { WildFlyElytronPasswordProvider.getInstance() };

            try {
                Provider vaultProvider = HashicorpVaultCredentialStoreProvider.getInstance();
                CredentialStore store = CredentialStore.getInstance("HashicorpVaultCredentialStore", vaultProvider);

                List<Class<? extends CredentialStoreExtension>> supportedTypes = store.getSupportedExtensionTypes();
                if (!supportedTypes.contains(HashicorpVaultCredentialStoreExtension.class)) {
                    throw HashiCorpVaultLogger.ROOT_LOGGER.hcVaultCredentialStoreExtensionMissing();
                }

                HashicorpVaultCredentialStoreExtension extension =
                        store.getExtensionInstance(HashicorpVaultCredentialStoreExtension.class);
                extension.setSslContext(sslContext);

                store.initialize(attributes, protectionParameter, providers);
                return store;
            } catch (CredentialStoreException e) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.failedToInitializeHashiCorpVaultCredentialStore(e.getMessage(), e);
            } catch (Exception e) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.failedToInitializeCredentialStoreService(e.getMessage(), e);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Runtime operations
    // -------------------------------------------------------------------------

    private void readAliasesOperation(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException {
        try {
            Set<String> aliases;
            ModelNode pathNode = PATH.resolveModelAttribute(context, operation);
            String path = pathNode.asStringOrNull();

            // "#" means root of the default mount in the new alias format
            if (path == null || path.trim().isEmpty()) {
                path = "#";
            }

            boolean recursive = RECURSIVE.resolveModelAttribute(context, operation).asBooleanOrNull();
            int recursiveDepth = recursive ? RECURSIVE_DEPTH.resolveModelAttribute(context, operation).asIntOrNull() : 0;
            int maxNumberOfAliases = MAX_NUMBER_OF_ALIASES.resolveModelAttribute(context, operation).asIntOrNull();

            List<Class<? extends CredentialStoreExtension>> supportedTypes = credentialStore.getSupportedExtensionTypes();
            if (!supportedTypes.contains(HashicorpVaultCredentialStoreExtension.class)) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.vaultCredentialStoreExtensionNotSupported();
            }
            HashicorpVaultCredentialStoreExtension hccse = credentialStore.getExtensionInstance(HashicorpVaultCredentialStoreExtension.class);
            aliases = hccse.getAliases(path, recursive, recursiveDepth, maxNumberOfAliases);

            List<ModelNode> list = new ArrayList<>();
            for (String alias : aliases) {
                list.add(new ModelNode(alias));
            }
            context.getResult().set(list);
        } catch (CredentialStoreException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unableToReadAliases(e.getMessage(), e);
        }
    }

    private void addAliasOperation(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException {
        try {
            String alias = ALIAS.resolveModelAttribute(context, operation).asString();
            String secretValue = SECRET_VALUE.resolveModelAttribute(context, operation).asStringOrNull();

            if (credentialStore.exists(alias, PasswordCredential.class)) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.credentialAliasAlreadyExists(alias);
            }

            if (secretValue != null) {
                PasswordCredential credential = createCredentialFromPassword(secretValue);
                credentialStore.store(alias, credential);
                credentialStore.flush();
            } else {
                throw HashiCorpVaultLogger.ROOT_LOGGER.secretValueRequired();
            }
        } catch (UnsupportedCredentialTypeException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unsupportedCredentialType(e.getMessage(), e);
        } catch (CredentialStoreException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unableToAddAlias(e.getMessage(), e);
        }
    }

    private void removeAliasOperation(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException {
        try {
            String alias = ALIAS.resolveModelAttribute(context, operation).asString();

            if (!credentialStore.exists(alias, PasswordCredential.class)) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.credentialAliasDoesNotExist(alias);
            }

            credentialStore.remove(alias, PasswordCredential.class);
            credentialStore.flush();
        } catch (CredentialStoreException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unableToRemoveAlias(e.getMessage(), e);
        }
    }


    private static class RuntimeOperationHandler implements OperationStepHandler {

        private final CredentialStoreOperation operation;

        RuntimeOperationHandler(CredentialStoreOperation operation) {
            this.operation = operation;
        }

        @Override
        public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
            context.addStep(new OperationStepHandler() {
                @Override
                public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
                    final String name = context.getCurrentAddressValue();

                    // Get the credential store from the service registry
                    ServiceName serviceName = CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
                    ServiceRegistry serviceRegistry = context.getServiceRegistry(false);
                    ServiceController<?> serviceController = serviceRegistry.getService(serviceName);

                    if (serviceController == null) {
                        throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreResourceNotFound(name);
                    }

                    CredentialStore credentialStore = (CredentialStore) serviceController.getValue();
                    if (credentialStore == null) {
                        throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreResourceNotAvailable(name);
                    }

                    RuntimeOperationHandler.this.operation.execute(context, operation, credentialStore);
                }
            }, OperationContext.Stage.RUNTIME);
        }
    }

    @FunctionalInterface
    private interface CredentialStoreOperation {
        void execute(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException;
    }
}
