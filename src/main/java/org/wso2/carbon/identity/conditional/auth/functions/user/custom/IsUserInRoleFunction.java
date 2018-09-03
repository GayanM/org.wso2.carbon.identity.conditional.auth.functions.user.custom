package org.wso2.carbon.identity.conditional.auth.functions.user.custom;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;

@FunctionalInterface
public interface IsUserInRoleFunction {

    boolean isUserInRole(JsAuthenticatedUser user, String roleName);

}
