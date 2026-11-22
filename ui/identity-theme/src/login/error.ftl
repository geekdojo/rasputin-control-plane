<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/error.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): copy only, inside the Rasputin frame; the
  message announced with role="alert" and escaped, never ?no_esc.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("errorTitle")}
    <#elseif section = "form">
        <div id="kc-error-message" role="alert">
            <p class="instruction kc-feedback-text">${message.summary}</p>
            <#if traceId??>
                <p class="instruction rasp-hint" id="traceId">${msg("traceIdSupportMessage", traceId)}</p>
            </#if>
            <#if !skipLink?? && client?? && client.baseUrl?has_content>
                <p><a id="backToApplication" href="${client.baseUrl}">${msg("backToApplication")}</a></p>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
