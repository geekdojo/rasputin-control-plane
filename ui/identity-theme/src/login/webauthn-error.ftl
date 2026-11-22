<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/webauthn-error.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the retry's inline script and onclick
  moved to js/rasputin-page.js (data-rasputin-retry, with the execution in data-execution);
  messages escaped, never ?no_esc; no positive tabindex.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("webauthn-error-title")}
    <#elseif section = "form">

        <form id="kc-error-credential-form" class="${properties.kcFormClass!}" action="${url.loginAction}"
              method="post">
            <input type="hidden" id="executionValue" name="authenticationExecution"/>
            <input type="hidden" id="isSetRetry" name="isSetRetry"/>
        </form>

        <button type="button" data-rasputin-retry data-execution="${execution}"
               class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
               name="try-again" id="kc-try-again">${msg("doTryAgain")}</button>

        <#if isAppInitiatedAction??>
            <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-webauthn-settings-form" method="post">
                <button type="submit"
                        class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                        id="cancelWebAuthnAIA" name="cancel-aia" value="true">${msg("doCancel")}
                </button>
            </form>
        </#if>

    </#if>
</@layout.registrationLayout>
