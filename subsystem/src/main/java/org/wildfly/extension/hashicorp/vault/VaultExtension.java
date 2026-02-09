/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;

import java.util.regex.Pattern;

import org.jboss.as.controller.Extension;
import org.jboss.as.controller.ExtensionContext;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SubsystemModel;
import org.jboss.as.controller.SubsystemRegistration;
import org.jboss.as.version.Stability;

/**
 * WildFly extension that provides HashiCorp Vault Support
 *
 */
public final class VaultExtension implements Extension {

    /**
     * The name of our subsystem within the model.
     */
    static final String SUBSYSTEM_NAME = "hashicorp-vault";
    private static final Stability FEATURE_STABILITY = Stability.COMMUNITY;
    static final ModelVersion CURRENT_MODEL_VERSION = ModelVersion.create(1, 0, 0);

    static final PathElement SUBSYSTEM_PATH = PathElement.pathElement(SUBSYSTEM, SUBSYSTEM_NAME);
    //private static final String RESOURCE_NAME = VaultExtension.class.getPackage().getName() + ".LocalDescriptions";
    
    public VaultExtension() {
    }

    /**
     * Model for the 'vault' subsystem.
     */
    public enum VaultSubsystemModel implements SubsystemModel {
        VERSION_1_0_0(1, 0, 0),
        ;

        static final VaultSubsystemModel CURRENT = VERSION_1_0_0;

        private final ModelVersion version;

        VaultSubsystemModel(int major, int minor, int micro) {
            this.version = ModelVersion.create(major, minor, micro);
        }

        @Override
        public ModelVersion getVersion() {
            return this.version;
        }
    }

    @Override
    public Stability getStability() {
        return FEATURE_STABILITY;
    }

    /**
     * Pattern for VAULT expressions: ${HC_VAULT::hashicorp-vault-credential-store-name:alias}
     */
    private static final Pattern VAULT_EXPRESSION_PATTERN = Pattern.compile("\\$\\{HC_VAULT::.+}");

    @Override
    public void initialize(ExtensionContext context) {
        final SubsystemRegistration subsystem = context.registerSubsystem(SUBSYSTEM_NAME, CURRENT_MODEL_VERSION);
        subsystem.registerSubsystemModel(new VaultSubsystemDefinition());
        subsystem.registerXMLElementWriter(VaultSubsystemParser_1_0.INSTANCE);

        VaultExpressionResolver vaultResolver = new VaultExpressionResolver();
        context.registerExpressionResolverExtension(() -> vaultResolver, VAULT_EXPRESSION_PATTERN, false);
    }
    
    @Override
    public void initializeParsers(org.jboss.as.controller.parsing.ExtensionParsingContext context) {
        context.setSubsystemXmlMapping(SUBSYSTEM_NAME, VaultSubsystemParser_1_0.NAMESPACE, VaultSubsystemParser_1_0.INSTANCE);
    }
    
    public static PathElement createPath(String name) {
        return PathElement.pathElement(name);
    }
}
