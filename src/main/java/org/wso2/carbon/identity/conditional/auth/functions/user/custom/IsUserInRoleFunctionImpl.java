package org.wso2.carbon.identity.conditional.auth.functions.user.custom;

import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasRoleFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.custom.internal.CustomUserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class IsUserInRoleFunctionImpl extends HasRoleFunctionImpl implements IsUserInRoleFunction {

    private static final Log LOG = LogFactory.getLog(IsUserInRoleFunctionImpl.class);
    private static final String ROLE_CLAIM = "http://wso2.org/claims/role";

    @Override
    public boolean isUserInRole(JsAuthenticatedUser user, String roleName) {

        if (!user.getWrapped().isFederatedUser()) {
            return hasRole(user, roleName);
        }
        try {
            return getUserRoles(user).stream().anyMatch(e -> e.equals(roleName) );
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        }
        return Boolean.FALSE;
    }

    private List<String> getUserRoles (JsAuthenticatedUser user) throws FrameworkException {

        Map<ClaimMapping, String> userAttributes = user.getWrapped().getUserAttributes();
        for (Map.Entry<ClaimMapping, String> e: userAttributes.entrySet()) {
            if(!ROLE_CLAIM.equals(e.getKey().getLocalClaim().getClaimUri())) {
                continue;
            }
            String roleStr = e.getValue();
            if (StringUtils.isBlank(roleStr)) {
                return ListUtils.EMPTY_LIST;
            }
            return Arrays.asList(roleStr.split(getMultiAttributeSeperator(user)));
        }
        return ListUtils.EMPTY_LIST;
    }

    private String getMultiAttributeSeperator(JsAuthenticatedUser user) throws FrameworkException {

        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        UserRealm userRealm = getUserRealm(tenantDomain);
        UserStoreManager userStore = getUserStoreManager(tenantDomain, userRealm, userStoreDomain);

        RealmConfiguration realmConfiguration = userStore.getRealmConfiguration();

        return realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
    }

    private UserRealm getUserRealm(String tenantDomain) throws FrameworkException {

        UserRealm realm;
        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(CustomUserFunctionsServiceHolder.getInstance()
                    .getRegistryService(), CustomUserFunctionsServiceHolder.getInstance().getRealmService(), tenantDomain);
        } catch (CarbonException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the Realm for " + tenantDomain + " to retrieve user roles", e);
        }
        return realm;
    }

    private UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain)
            throws FrameworkException {

        UserStoreManager userStore = null;
        try {
            if (StringUtils.isNotBlank(userDomain)) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userDomain);
            } else {
                userStore = realm.getUserStoreManager();
            }
            if (userStore == null) {
                throw new FrameworkException(
                        String.format("Invalid user store domain (given : %s) or tenant domain (given: %s).",
                                userDomain, tenantDomain));
            }
        } catch (UserStoreException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the UserStoreManager from Realm for " + tenantDomain
                            + " to retrieve user roles", e);
        }
        return userStore;
    }
}
