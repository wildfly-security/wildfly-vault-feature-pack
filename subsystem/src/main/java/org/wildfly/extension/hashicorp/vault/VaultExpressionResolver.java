/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.hashicorp.vault;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.VAULT_CREDENTIAL_STORE_API_CAPABILITY;

import org.wildfly.extension.hashicorp.vault._private.HashiCorpVaultLogger;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.extension.ExpressionResolverExtension;
import org.wildfly.common.function.ExceptionFunction;

import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * An expression resolver that resolves expressions by reading secrets from a HashiCorp Vault credential store.
 * <p>
 * Expression format: {@code ${HC_VAULT::credential-store-name:alias}}
 * </p>
 * <ul>
 *   <li>{@code credential-store-name} - the name of a credential-store resource in the hashicorp-vault subsystem</li>
 *   <li>{@code alias} - the alias of the secret in that credential store</li>
 * </ul>
 */
public final class VaultExpressionResolver implements ExpressionResolverExtension {

    private static final String PREFIX = "HC_VAULT";

    @Override
    public void initialize(OperationContext context) {
        // No op
    }

    // Expect format: ${HC_VAULT::hashicorpVaultCredentialStoreName:alias}
    @Override
    public String resolveExpression(String expression, OperationContext context) {
        checkNotNullParam("expression", expression);
        checkNotNullParam("context", context);
        if (expression.length() < 10) {
            return null;
        }
        if (!expression.startsWith("${") || !expression.endsWith("}")) {
            return null;
        }
        String inner = expression.substring(2, expression.length() - 1);
        if (!inner.startsWith(PREFIX + "::")) {
            return null;
        }

        String afterPrefix = inner.substring(PREFIX.length() + 2);
        int colon = afterPrefix.indexOf(':');
        String credentialStoreName = afterPrefix.substring(0, colon);
        String alias = afterPrefix.substring(colon + 1);

        if (alias.isEmpty()) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    HashiCorpVaultLogger.ROOT_LOGGER.invalidVaultExpressionEmptyAlias(expression));
        }

        if (context.getCurrentStage() == OperationContext.Stage.MODEL) {
            throw new ExpressionResolver.ExpressionResolutionServerException(
                    HashiCorpVaultLogger.ROOT_LOGGER.vaultExpressionResolutionNotSupportedInModelStage());
        }

        CredentialStore credentialStore = getCredentialStore(context, credentialStoreName, expression);

        // retrieve the credential from the resolved hashicorp vault credential store
        PasswordCredential credential;
        try {
            credential = credentialStore.retrieve(alias, PasswordCredential.class);
        } catch (CredentialStoreException e) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    HashiCorpVaultLogger.ROOT_LOGGER.failedToRetrieveAliasFromCredentialStore(alias, credentialStoreName, e.getMessage()), e);
        }

        if (credential == null) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    HashiCorpVaultLogger.ROOT_LOGGER.aliasNotFoundInCredentialStore(alias, credentialStoreName, expression));
        }

        return getPasswordFromObtainedCredential(credential, alias, credentialStoreName);
    }

    private static CredentialStore getCredentialStore(OperationContext context, String credentialStoreName, String expression) {
        try {
            @SuppressWarnings("unchecked")
            ExceptionFunction<OperationContext, CredentialStore, OperationFailedException> doohickey =
                    context.getCapabilityRuntimeAPI(VAULT_CREDENTIAL_STORE_API_CAPABILITY,
                            credentialStoreName, ExceptionFunction.class);
            return doohickey.apply(context);
        } catch (ExpressionResolver.ExpressionResolutionUserException | ExpressionResolver.ExpressionResolutionServerException e) {
            throw e;
        } catch (IllegalArgumentException | IllegalStateException e) {
            // getCapabilityRuntimeAPI throws IllegalStateException when the capability is unknown/not registered,
            // and IllegalArgumentException if the capability exists but does not expose a runtime API or is not dynamic.
            // In either case, the requested vault credential store is not available.
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreNotAvailableDetail(credentialStoreName, e.getMessage()), e);
        } catch (OperationFailedException e) {
            throw new ExpressionResolver.ExpressionResolutionServerException(
                    HashiCorpVaultLogger.ROOT_LOGGER.serviceRegistryUnavailableForVaultExpression(), e);
        }
    }

    private static String getPasswordFromObtainedCredential(PasswordCredential credential, String alias, String credentialStoreName) {
        Password password = credential.getPassword();
        if (password == null) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    HashiCorpVaultLogger.ROOT_LOGGER.credentialHasNoPassword(alias, credentialStoreName));
        }

        if (!(password instanceof ClearPassword)) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    HashiCorpVaultLogger.ROOT_LOGGER.credentialNotClearPassword(alias, credentialStoreName));
        }
        return new String((((ClearPassword) password).getPassword()));
    }
}
