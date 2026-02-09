/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_STORE_CAPABILITY;
import static org.wildfly.common.Assert.checkNotNullParam;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.extension.ExpressionResolverExtension;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;

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
                    "Invalid VAULT expression: alias is empty in " + expression);
        }

        if (context.getCurrentStage() == OperationContext.Stage.MODEL) {
            throw new ExpressionResolver.ExpressionResolutionServerException(
                    "VAULT expression resolution is not supported in MODEL stage");
        }

        CredentialStore credentialStore = getCredentialStore(context, credentialStoreName, expression);

        // retrieve the credential from the resolved hahsicorp vault credential store
        PasswordCredential credential;
        try {
            credential = credentialStore.retrieve(alias, PasswordCredential.class);
        } catch (CredentialStoreException e) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    "Failed to retrieve alias '" + alias + "' from credential store '" + credentialStoreName + "': " + e.getMessage(), e);
        }

        if (credential == null) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    "Alias '" + alias + "' not found in credential store '" + credentialStoreName + "' for expression: " + expression);
        }

        return getPasswordFromObtainedCredential(credential, alias, credentialStoreName);
    }

    private static CredentialStore getCredentialStore(OperationContext context, String credentialStoreName, String expression) {
        CredentialStore credentialStore;
        try {
            ServiceName serviceName = context.getCapabilityServiceName(CREDENTIAL_STORE_CAPABILITY, credentialStoreName, CredentialStore.class);
            ServiceRegistry registry = context.getServiceRegistry(false);
            if (registry == null) {
                throw new ExpressionResolver.ExpressionResolutionServerException(
                        "Service registry is not available for VAULT expression resolution");
            }
            ServiceController<?> controller = registry.getService(serviceName);
            if (controller == null) {
                throw new ExpressionResolver.ExpressionResolutionUserException(
                        "Credential store '" + credentialStoreName + "' is not installed for the expression: " + expression);
            }
            Object value = controller.getValue();
            if (value == null) {
                throw new ExpressionResolver.ExpressionResolutionUserException(
                        "Credential store service '" + credentialStoreName + "' has not started for the expression: " + expression);
            }
            credentialStore = (CredentialStore) value;
        } catch (ExpressionResolver.ExpressionResolutionUserException | ExpressionResolver.ExpressionResolutionServerException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    "Credential store '" + credentialStoreName + "' is not available: " + e.getMessage(), e);
        }
        return credentialStore;
    }

    private static String getPasswordFromObtainedCredential(PasswordCredential credential, String alias, String credentialStoreName) {
        Password password = credential.getPassword();
        if (password == null) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    "Credential for alias '" + alias + "' in credential store '" + credentialStoreName + "' has no password");
        }

        if (!(password instanceof ClearPassword)) {
            throw new ExpressionResolver.ExpressionResolutionUserException(
                    "Credential for alias '" + alias + "' in credential store '" + credentialStoreName + "' is not of a type clear password");
        }
        return new String((((ClearPassword) password).getPassword()));
    }
}
