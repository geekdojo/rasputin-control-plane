<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/saml-post-form.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the inline window.onload submit moved to
  js/rasputin-autosubmit.js (form[data-rasputin-autosubmit]); copy only, inside the Rasputin
  frame.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("saml.post-form.title")}
    <#elseif section = "form">
        <p>${msg("saml.post-form.message")}</p>
        <form name="saml-post-binding" id="saml-post-binding" data-rasputin-autosubmit method="post" action="${samlPost.url}">
            <#if samlPost.SAMLRequest??>
                <input type="hidden" name="SAMLRequest" value="${samlPost.SAMLRequest}"/>
            </#if>
            <#if samlPost.SAMLResponse??>
                <input type="hidden" name="SAMLResponse" value="${samlPost.SAMLResponse}"/>
            </#if>
            <#if samlPost.relayState??>
                <input type="hidden" name="RelayState" value="${samlPost.relayState}"/>
            </#if>

            <noscript>
                <p>${msg("saml.post-form.js-disabled")}</p>
                <input type="submit" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" value="${msg("doContinue")}"/>
            </noscript>
        </form>
        <script type="module" src="${url.resourcesPath}/js/rasputin-autosubmit.js"></script>
    </#if>
</@layout.registrationLayout>
