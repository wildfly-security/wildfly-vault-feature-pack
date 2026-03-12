/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.PersistentResourceXMLDescription.builder;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.PersistentResourceXMLParser;

/**
 * XML parser for the HashiCorp Vault subsystem schema version 1.0.
 */
public class VaultSubsystemParser_1_0 extends PersistentResourceXMLParser {
    
    public static final VaultSubsystemParser_1_0 INSTANCE = new VaultSubsystemParser_1_0();

    public static final String NAMESPACE = "urn:wildfly:hashicorp-vault:community:1.0";


    @Override
    public PersistentResourceXMLDescription getParserDescription() {
        return builder(VaultExtension.SUBSYSTEM_PATH, NAMESPACE)
                .addChild(
                        builder(PathElement.pathElement("credential-store"))
                                .setXmlElementName("credential-store")
                                .setNameAttributeName("name")
                                .addAttributes(CredentialStoreDefinition.ATTRIBUTES.toArray(new org.jboss.as.controller.AttributeDefinition[0]))
                                .build()
                )
                .build();
    }
}
