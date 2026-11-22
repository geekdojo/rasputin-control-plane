<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-page-expired.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): copy only, inside the Rasputin frame: each
  choice is a link with its own words, not "click here".
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("pageExpiredTitle")}
    <#elseif section = "form">
        <p id="instruction1" class="instruction">${msg("pageExpiredMsg1")}</p>
        <p class="rasp-links">
            <a id="loginRestartLink" href="${url.loginRestartFlowUrl}">${msg("rasputinPageExpiredRestart")}</a>
            <a id="loginContinueLink" href="${url.loginAction}">${msg("rasputinPageExpiredContinue")}</a>
        </p>
    </#if>
</@layout.registrationLayout>
