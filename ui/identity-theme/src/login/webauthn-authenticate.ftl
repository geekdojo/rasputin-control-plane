<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/webauthn-authenticate.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the inline module moved to js/rasputin-
  webauthn-authenticate.js, which reads Keycloak's arguments from the button's data attributes;
  no "Create an account" link here (the sign-in page alone offers it, for the console); no
  positive tabindex.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("webauthn-login-title")}
    <#elseif section = "form">
        <div id="kc-form-webauthn" class="${properties.kcFormClass!}">
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
                            <p class="${properties.kcSelectAuthListItemTitle!}">${msg("webauthn-available-authenticators")}</p>
                        </#if>

                        <ul class="${properties.kcSelectAuthListClass!}">
                            <#list authenticators.authenticators as authenticator>
                                <li id="kc-webauthn-authenticator-item-${authenticator?index}" class="${properties.kcSelectAuthListItemClass!}">
                                    <span class="${properties.kcWebAuthnDefaultIcon!} ${properties.kcSelectAuthListItemIconPropertyClass!}" aria-hidden="true"></span>
                                    <span class="${properties.kcSelectAuthListItemBodyClass!}">
                                        <span id="kc-webauthn-authenticator-label-${authenticator?index}" class="${properties.kcSelectAuthListItemHeadingClass!}">${authenticator.label}</span>
                                        <span class="${properties.kcSelectAuthListItemDescriptionClass!}">
                                            <span id="kc-webauthn-authenticator-createdlabel-${authenticator?index}">${msg('webauthn-createdAt-label')}</span>
                                            <span id="kc-webauthn-authenticator-created-${authenticator?index}">${authenticator.createdAt}</span>
                                        </span>
                                    </span>
                                </li>
                            </#list>
                        </ul>
                    </#if>
                </#if>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <button id="authenticateWebAuthnButton" type="button" autofocus
                            data-is-user-identified="${isUserIdentified}"
                            data-challenge="${challenge}"
                            data-user-verification="${userVerification}"
                            data-rp-id="${rpId}"
                            data-create-timeout="${createTimeout?c}"
                            data-errmsg="${msg("webauthn-unsupported-browser-text")}"
                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("webauthn-doAuthenticate")}</button>
                </div>
            </div>
        </div>
        <script type="module" src="${url.resourcesPath}/js/rasputin-webauthn-authenticate.js"></script>
    </#if>
</@layout.registrationLayout>
