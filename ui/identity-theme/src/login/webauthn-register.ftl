<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/webauthn-register.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the inline module moved to js/rasputin-
  webauthn.js, which reads Keycloak's arguments from data attributes; THIS DEVICE, PHONE OR
  TABLET and SECURITY KEY choose the authenticator, and an in-page NAME field replaces
  window.prompt.
-->
<#import "template.ftl" as layout>
<#import "password-commons.ftl" as passwordCommons>

<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("webauthn-registration-title")}
    <#elseif section = "form">

        <form id="register" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
                <input type="hidden" id="attestationObject" name="attestationObject"/>
                <input type="hidden" id="publicKeyCredentialId" name="publicKeyCredentialId"/>
                <input type="hidden" id="authenticatorLabel" name="authenticatorLabel"/>
                <input type="hidden" id="transports" name="transports"/>
                <input type="hidden" id="authenticatorAttachment" name="authenticatorAttachment"/>
                <input type="hidden" id="error" name="error"/>
                <@passwordCommons.logoutOtherSessions/>
            </div>
        </form>

        <div id="rasputin-passkey" class="${properties.kcFormClass!}"
             data-challenge="${challenge}"
             data-userid="${userid}"
             data-username="${username}"
             data-signature-algorithms="<#list signatureAlgorithms as sigAlg>${sigAlg?c}<#sep>,</#sep></#list>"
             data-rp-entity-name="${rpEntityName}"
             data-rp-id="${rpId}"
             data-attestation-conveyance-preference="${attestationConveyancePreference}"
             data-authenticator-attachment="${authenticatorAttachment}"
             data-require-resident-key="${requireResidentKey}"
             data-resident-key="${residentKey}"
             data-user-verification-requirement="${userVerificationRequirement}"
             data-create-timeout="${createTimeout?c}"
             data-exclude-credential-ids="${excludeCredentialIds}"
             data-init-label="${msg("webauthn-registration-init-label")}"
             data-errmsg="${msg("webauthn-unsupported-browser-text")}">
            <div class="${properties.kcFormGroupClass!}">
                <label for="rasputin-passkey-name" class="${properties.kcLabelClass!}">${msg("rasputinPasskeyName")}</label>
                <input type="text" id="rasputin-passkey-name" class="${properties.kcInputClass!}" autocomplete="off"
                       placeholder="${msg("webauthn-registration-init-label")}" aria-describedby="rasputin-passkey-name-hint"/>
                <p id="rasputin-passkey-name-hint" class="rasp-hint">${msg("rasputinPasskeyNameHint")}</p>
            </div>
            <p class="rasp-hint">${msg("rasputinPasskeyChoose")}</p>
            <div class="${properties.kcFormButtonsClass!}">
                <button type="button" id="rasputin-passkey-this-device" data-rasputin-passkey-choice="this-device"
                        class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}">${msg("rasputinPasskeyThisDevice")}</button>
                <button type="button" id="rasputin-passkey-phone" data-rasputin-passkey-choice="phone-or-tablet"
                        class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}">${msg("rasputinPasskeyPhone")}</button>
                <button type="button" id="rasputin-passkey-security-key" data-rasputin-passkey-choice="security-key"
                        class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}">${msg("rasputinPasskeySecurityKey")}</button>
            </div>
        </div>
        <script type="module" src="${url.resourcesPath}/js/rasputin-webauthn.js"></script>

        <#if !isSetRetry?has_content && isAppInitiatedAction?has_content>
            <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-webauthn-settings-form"
                  method="post">
                <button type="submit"
                        class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                        id="cancelWebAuthnAIA" name="cancel-aia" value="true">${msg("doCancel")}
                </button>
            </form>
        </#if>

    </#if>
</@layout.registrationLayout>
