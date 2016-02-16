/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.auth.interceptor;

import com.google.common.collect.ArrayListMultimap;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.mss.HttpResponder;
import org.wso2.carbon.mss.Interceptor;
import org.wso2.carbon.mss.ServiceMethodInfo;
import org.wso2.carbon.security.annotation.Secure;
import org.wso2.carbon.security.jaas.CarbonCallbackHandler;
import org.wso2.carbon.security.jaas.CarbonPermission;

import java.lang.reflect.Method;
import java.security.AccessControlException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;

/**
 *
 */
@Component(
        name = "org.wso2.carbon.auth.interceptor.MSAuthInterceptor",
        service = Interceptor.class,
        immediate = true
)
public class MSAuthInterceptor implements Interceptor {

    private static final Logger log = LoggerFactory.getLogger(MSAuthInterceptor.class);

    @Override
    public boolean preCall(HttpRequest httpRequest, HttpResponder httpResponder, ServiceMethodInfo serviceMethodInfo) {

        CallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);

        LoginContext loginContext;
        try {
            loginContext = new LoginContext("CarbonSecurityConfig", callbackHandler);

        } catch (LoginException e) {
            log.error("Error occurred while initiating login context.", e);
            sendInternalServerError(httpResponder);
            return false;
        }

        try {
            loginContext.login();
            //TODO set LoginContext to CarbonContext

        } catch (LoginException e) {
            sendUnauthorized(httpResponder);
            return false;
        }

        // Authorization

        if (serviceMethodInfo.getMethod().isAnnotationPresent(Secure.class)) {

            if (!this.isAuthorized(loginContext.getSubject(), buildCarbonPermission(serviceMethodInfo))) {
                sendUnauthorized(httpResponder);
                return false;
            }
        }

        return true;
    }

    @Override
    public void postCall(HttpRequest httpRequest, HttpResponseStatus httpResponseStatus,
                         ServiceMethodInfo serviceMethodInfo) {

    }

    private boolean isAuthorized(Subject subject, final CarbonPermission requiredPermission) {

        final SecurityManager securityManager;

        if (System.getSecurityManager() == null) {
            securityManager = new SecurityManager();
        } else {
            securityManager = System.getSecurityManager();
        }

        try {
            Subject.doAsPrivileged(subject, (PrivilegedExceptionAction) () -> {
                securityManager.checkPermission(requiredPermission);
                return null;
            }, null);
            return true;
        } catch (AccessControlException ace) {
            return false;
        } catch (PrivilegedActionException pae) {
            return false;
        }
    }

    private void sendUnauthorized(HttpResponder httpResponder) {
        httpResponder.sendStatus(HttpResponseStatus.UNAUTHORIZED, ArrayListMultimap.create());
    }

    private void sendInternalServerError(HttpResponder httpResponder) {
        httpResponder.sendStatus(HttpResponseStatus.INTERNAL_SERVER_ERROR, ArrayListMultimap.create());
    }

    private CarbonPermission buildCarbonPermission(ServiceMethodInfo serviceMethodInfo) {

        StringBuilder permissionBuilder = new StringBuilder();
        permissionBuilder.append(serviceMethodInfo.getMethodName()).append(".")
                .append(serviceMethodInfo.getMethod().getName());

        return new CarbonPermission(permissionBuilder.toString(), getAction(serviceMethodInfo.getMethod()));
    }

    private String getAction(Method method) {

        if (method.isAnnotationPresent(GET.class)) {
            return HttpMethod.GET;
        } else if (method.isAnnotationPresent(POST.class)) {
            return HttpMethod.POST;
        } else if (method.isAnnotationPresent(PUT.class)) {
            return HttpMethod.PUT;
        } else if (method.isAnnotationPresent(DELETE.class)) {
            return HttpMethod.DELETE;
        }
        return null;
    }

}
