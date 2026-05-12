/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.hashicorp.vault._private;

import static org.jboss.logging.Logger.Level.INFO;
import static org.jboss.logging.Logger.Level.WARN;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.GeneralSecurityException;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.msc.service.StartException;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * Log messages and exceptions for the HashiCorp Vault subsystem.
 */
@MessageLogger(projectCode = "WFLYHCVT", length = 4)
public interface HashiCorpVaultLogger extends BasicLogger {

    HashiCorpVaultLogger ROOT_LOGGER = Logger.getMessageLogger(MethodHandles.lookup(), HashiCorpVaultLogger.class,
            HashiCorpVaultLogger.class.getPackage().getName());

    @LogMessage(level = INFO)
    @Message(id = 1, value = "Activating WildFly HashiCorp Vault subsystem")
    void activatingHashiCorpVaultSubsystem();

    @LogMessage(level = WARN)
    @Message(id = 2, value = "Failed to roll back credential-reference update for HashiCorp Vault credential store")
    void credentialReferenceRollbackFailed(@Cause Exception e);

    @Message(id = 3, value = "Failed to create and initialize HashiCorp Vault credential store: extension is not available.")
    StartException hcVaultCredentialStoreExtensionMissing();

    @Message(id = 4, value = "Failed to start HashiCorp Vault credential store service.")
    StartException credentialStoreStartFailed(@Cause Exception e);

    @Message(id = 5, value = "Failed to stop HashiCorp Vault credential store service.")
    RuntimeException credentialStoreStopFailed(@Cause Exception e);

    @Message(id = 6, value = "HashiCorp Vault credential store service has not started.")
    IllegalStateException credentialStoreServiceNotStarted();

    @Message(id = 7, value = "Authentication context '%s' not found")
    OperationFailedException authenticationContextNotFound(String authenticationContextName);

    @Message(id = 8, value = "Authentication context '%s' not available")
    OperationFailedException authenticationContextNotAvailable(String authenticationContextName);

    @Message(id = 9, value = "Failed to obtain SSLContext from authentication context '%s'")
    OperationFailedException sslContextFromAuthenticationContextFailed(String authenticationContextName,
            @Cause GeneralSecurityException e);

    @Message(id = 10, value = "Failed to obtain credential from credential-reference")
    OperationFailedException failedToObtainCredentialFromReference(@Cause IOException e);

    @Message(id = 11, value = "Failed to initialize HashiCorp Vault credential store: %s")
    OperationFailedException failedToInitializeHashiCorpVaultCredentialStore(String reason,
            @Cause CredentialStoreException e);

    @Message(id = 12, value = "Failed to initialize HashiCorp Vault credential store service: %s")
    OperationFailedException failedToInitializeCredentialStoreService(String reason, @Cause Exception e);

    @Message(id = 13, value = "Unable to read aliases: %s")
    OperationFailedException unableToReadAliases(String reason, @Cause CredentialStoreException e);

    @Message(id = 14, value = "Credential alias '%s' already exists")
    OperationFailedException credentialAliasAlreadyExists(String alias);

    @Message(id = 15, value = "Secret value is required")
    OperationFailedException secretValueRequired();

    @Message(id = 16, value = "Unsupported credential type: %s")
    OperationFailedException unsupportedCredentialType(String reason, @Cause UnsupportedCredentialTypeException e);

    @Message(id = 17, value = "Unable to add alias: %s")
    OperationFailedException unableToAddAlias(String reason, @Cause CredentialStoreException e);

    @Message(id = 18, value = "Credential alias '%s' does not exist")
    OperationFailedException credentialAliasDoesNotExist(String alias);

    @Message(id = 19, value = "Unable to remove alias: %s")
    OperationFailedException unableToRemoveAlias(String reason, @Cause CredentialStoreException e);

    @Message(id = 20, value = "Credential store '%s' not found or not started")
    OperationFailedException credentialStoreResourceNotFound(String name);

    @Message(id = 21, value = "Credential store '%s' not available")
    OperationFailedException credentialStoreResourceNotAvailable(String name);

    @Message(id = 22, value = "HashiCorp Vault credential store extension is not available for this credential store")
    OperationFailedException vaultCredentialStoreExtensionNotSupported();

    @Message(id = 23, value = "Invalid VAULT expression: alias is empty in %s")
    String invalidVaultExpressionEmptyAlias(String expression);

    @Message(id = 24, value = "VAULT expression resolution is not supported in MODEL stage")
    String vaultExpressionResolutionNotSupportedInModelStage();

    @Message(id = 25, value = "Failed to retrieve alias '%s' from credential store '%s': %s")
    String failedToRetrieveAliasFromCredentialStore(String alias, String credentialStoreName, String detail);

    @Message(id = 26, value = "Alias '%s' not found in credential store '%s' for expression: %s")
    String aliasNotFoundInCredentialStore(String alias, String credentialStoreName, String expression);

    @Message(id = 27, value = "Service registry is not available for VAULT expression resolution")
    String serviceRegistryUnavailableForVaultExpression();

    @Message(id = 28, value = "Credential store '%s' is not installed for the expression: %s")
    String credentialStoreNotInstalled(String credentialStoreName, String expression);

    @Message(id = 29, value = "Credential store service '%s' has not started for the expression: %s")
    String credentialStoreServiceNotStartedForExpression(String credentialStoreName, String expression);

    @Message(id = 30, value = "Credential store '%s' is not available: %s")
    String credentialStoreNotAvailableDetail(String credentialStoreName, String detail);

    @Message(id = 31, value = "Credential for alias '%s' in credential store '%s' has no password")
    String credentialHasNoPassword(String alias, String credentialStoreName);

    @Message(id = 32, value = "Credential for alias '%s' in credential store '%s' is not of a type clear password")
    String credentialNotClearPassword(String alias, String credentialStoreName);
}
