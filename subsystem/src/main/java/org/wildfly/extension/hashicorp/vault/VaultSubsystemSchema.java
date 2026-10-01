/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.PersistentResourceXMLDescription.builder;

import java.util.EnumSet;
import java.util.Map;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.AttributeParser;
import org.jboss.as.controller.Feature;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.PersistentSubsystemSchema;
import org.jboss.as.controller.SubsystemSchema;
import org.jboss.as.controller.xml.VersionedNamespace;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.IntVersion;
import org.wildfly.extension.hashicorp.vault._private.HashiCorpVaultLogger;

/**
 * Enumeration of hashicorp-vault subsystem schema versions.
 */
public enum VaultSubsystemSchema implements PersistentSubsystemSchema<VaultSubsystemSchema> {
    VERSION_1_0(1),
    VERSION_1_0_COMMUNITY(1, Stability.COMMUNITY),
    VERSION_2_0(2),
    ;

    static final Map<Stability, VaultSubsystemSchema> CURRENT = Feature.map(EnumSet.of(VERSION_2_0));

    /** AttributeParser that always rejects the legacy 'authentication-context' attribute with a clear error. */
    private static final AttributeParser AUTHENTICATION_CONTEXT_REJECTING_PARSER = new AttributeParser() {
        @Override
        public void parseAndSetParameter(AttributeDefinition attribute, String value,
                ModelNode operation, XMLStreamReader reader) throws XMLStreamException {
            throw HashiCorpVaultLogger.ROOT_LOGGER.authenticationContextAttributeNotSupported();
        }
    };

    private final VersionedNamespace<IntVersion, VaultSubsystemSchema> namespace;

    VaultSubsystemSchema(int major) {
        this.namespace = SubsystemSchema.createSubsystemURN(VaultExtension.SUBSYSTEM_NAME, new IntVersion(major));
    }

    VaultSubsystemSchema(int major, Stability stability) {
        this.namespace = SubsystemSchema.createSubsystemURN(VaultExtension.SUBSYSTEM_NAME, stability, new IntVersion(major));
    }

    @Override
    public VersionedNamespace<IntVersion, VaultSubsystemSchema> getNamespace() {
        return this.namespace;
    }

    @Override
    public PersistentResourceXMLDescription getXMLDescription() {
        PersistentResourceXMLDescription.PersistentResourceXMLBuilder credentialStoreBuilder =
                builder(PathElement.pathElement("credential-store"))
                        .setXmlElementName("credential-store")
                        .setNameAttributeName("name");

        if (this == VERSION_1_0 || this == VERSION_1_0_COMMUNITY) {
            // Legacy schemas: recognise authentication-context but reject it immediately with a clear error
            // directing the user to migrate to the client-ssl-context attribute.
            credentialStoreBuilder
                    .addAttributes(CredentialStoreDefinition.HOST_NAME_DEF, CredentialStoreDefinition.NAMESPACE_DEF,
                            CredentialStoreDefinition.CREDENTIAL_REFERENCE)
                    .addAttribute(CredentialStoreDefinition.AUTHENTICATION_CONTEXT_LEGACY_DEF,
                            AUTHENTICATION_CONTEXT_REJECTING_PARSER);
        } else {
            // Current schema (2.0+): use client-ssl-context
            credentialStoreBuilder
                    .addAttributes(CredentialStoreDefinition.ATTRIBUTES.toArray(new AttributeDefinition[0]));
        }

        return builder(VaultExtension.SUBSYSTEM_PATH, this.getNamespace())
                .addChild(credentialStoreBuilder.build())
                .build();
    }
}
