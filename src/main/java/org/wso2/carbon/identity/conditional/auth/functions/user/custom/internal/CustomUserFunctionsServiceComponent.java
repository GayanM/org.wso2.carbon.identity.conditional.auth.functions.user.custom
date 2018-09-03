/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user.custom.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.user.*;
import org.wso2.carbon.identity.conditional.auth.functions.user.custom.IsUserInRoleFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.custom.IsUserInRoleFunctionImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and de-registration of user conditional auth
 * functions.
 */

@Component(
        name = "identity.conditional.auth.functions.user.custom.component",
        immediate = true
)
public class CustomUserFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(CustomUserFunctionsServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            IsUserInRoleFunction isUserInRoleFunction = new IsUserInRoleFunctionImpl();
            JsFunctionRegistry jsFunctionRegistry = CustomUserFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isUserInRole",
                    isUserInRoleFunction);
        } catch (Throwable e) {
            LOG.error("Error in registering isUserInRole function");
        }

    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = CustomUserFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isUserInRole");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is set in the conditional authentication user functions bundle");
        }
        CustomUserFunctionsServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is unset in the conditional authentication user functions bundle");
        }
        CustomUserFunctionsServiceHolder.getInstance().setRealmService(null);
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        CustomUserFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        CustomUserFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

}
