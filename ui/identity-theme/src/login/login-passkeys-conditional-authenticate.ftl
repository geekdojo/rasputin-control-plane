<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-passkeys-conditional-authenticate.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the inline module and the double-submit
  guard moved to js/rasputin-passkeys.js and js/rasputin-page.js, which read Keycloak's
  arguments from data attributes and show the field or the button with the hidden attribute; no
  "Create an account" link; no positive tabindex; messages escaped, never ?no_esc.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("passkey-login-title")}
    <#elseif section = "form">
        <form id="webauth" action="${url.loginAction}" method="post">
            <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
            <input type="hidden" id="authenticatorData" name="authenticatorData"/>
            <input type="hidden" id="signature" name="signature"/>
            <input type="hidden" id="credentialId" name="credentialId"/>
            <input type="hidden" id="userHandle" name="userHandle"/>
            <input type="hidden" id="error" name="error"/>
        </form>

        <div class="${properties.kcFormGroupClass!}">
            <#if authenticators??>
                <form id="authn_select" class="${properties.kcFormClass!}">
                    <#list authenticators.authenticators as authenticator>
                        <input type="hidden" name="authn_use_chk" value="${authenticator.credentialId}"/>
                    </#list>
                </form>

                <#if shouldDisplayAuthenticators?? && shouldDisplayAuthenticators>
                    <#if authenticators.authenticators?size gt 1>
                        <p class="${properties.kcSelectAuthListItemTitle!}">${msg("passkey-available-authenticators")}</p>
                    </#if>

                    <ul class="${properties.kcSelectAuthListClass!}">
                        <#list authenticators.authenticators as authenticator>
                            <li id="kc-webauthn-authenticator-item-${authenticator?index}" class="${properties.kcSelectAuthListItemClass!}">
                                <span class="${properties.kcWebAuthnDefaultIcon!} ${properties.kcSelectAuthListItemIconPropertyClass!}" aria-hidden="true"></span>
                                <span class="${properties.kcSelectAuthListItemBodyClass!}">
                                    <span id="kc-webauthn-authenticator-label-${authenticator?index}" class="${properties.kcSelectAuthListItemHeadingClass!}">${authenticator.label}</span>
                                    <span class="${properties.kcSelectAuthListItemDescriptionClass!}">
                                        <span id="kc-webauthn-authenticator-createdlabel-${authenticator?index}">${msg('passkey-createdAt-label')}</span>
                                        <span id="kc-webauthn-authenticator-created-${authenticator?index}">${authenticator.createdAt}</span>
                                    </span>
                                </span>
                            </li>
                        </#list>
                    </ul>
                </#if>
            </#if>

            <div id="kc-form">
                <div id="kc-form-wrapper">
                    <#if realm.password>
                        <form id="kc-form-login" data-rasputin-once="login" action="${url.loginAction}" method="post" hidden>
                            <#if !usernameHidden??>
                                <div class="${properties.kcFormGroupClass!}">
                                    <label for="username" class="${properties.kcLabelClass!}">${msg("passkey-autofill-select")}</label>
                                    <input id="username"
                                        aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                                        class="${properties.kcInputClass!}" name="username"
                                        value="${(login.username!'')}"
                                        autocomplete="username webauthn"
                                        type="text" autofocus
                                        dir="ltr"/>
                                    <#if messagesPerField.existsError('username')>
                                        <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                            ${messagesPerField.get('username')}
                                        </span>
                                    </#if>
                                </div>
                            </#if>
                        </form>
                    </#if>
                    <div id="kc-form-passkey-button" class="${properties.kcFormButtonsClass!}" hidden>
                        <button id="authenticateWebAuthnButton" type="button"
                            data-rasputin-passkeys="conditional"
                            data-is-user-identified="${isUserIdentified}"
                            data-challenge="${challenge}"
                            data-user-verification="${userVerification}"
                            data-rp-id="${rpId}"
                            data-create-timeout="${createTimeout?c}"
                            data-errmsg="${msg("webauthn-unsupported-browser-text")}"
                            data-conditional-errmsg="${msg("passkey-unsupported-browser-text")}"
                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("passkey-doAuthenticate")}</button>
                    </div>
                </div>
            </div>
        </div>
        <script type="module" src="${url.resourcesPath}/js/rasputin-passkeys.js"></script>
    </#if>

</@layout.registrationLayout>
