<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/passkeys.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the inline module moved to
  js/rasputin-passkeys.js, which reads its arguments from this element's data attributes; the
  passkey button is a button, after an "or" divider.
-->
<#macro conditionalUIData>
    <#if enableWebAuthnConditionalUI?has_content>
        <form id="webauth" action="${url.loginAction}" method="post">
            <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
            <input type="hidden" id="authenticatorData" name="authenticatorData"/>
            <input type="hidden" id="signature" name="signature"/>
            <input type="hidden" id="credentialId" name="credentialId"/>
            <input type="hidden" id="userHandle" name="userHandle"/>
            <input type="hidden" id="error" name="error"/>
        </form>
        <#if authenticators??>
            <form id="authn_select" class="${properties.kcFormClass!}">
                <#list authenticators.authenticators as authenticator>
                    <input type="hidden" name="authn_use_chk" value="${authenticator.credentialId}"/>
                </#list>
            </form>
        </#if>
        <p class="rasp-divider"><span>${msg("orLabel")}</span></p>
        <button id="authenticateWebAuthnButton" type="button" class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcMarginTopClass!}"
                data-rasputin-passkeys="sign-in"
                data-is-user-identified="${isUserIdentified}"
                data-challenge="${challenge}"
                data-user-verification="${userVerification}"
                data-rp-id="${rpId}"
                data-create-timeout="${createTimeout?c}"
                data-mediation="${mediation!'conditional'}"
                data-authenticator-attachment="${authenticatorAttachment}"
                data-errmsg="${msg("webauthn-unsupported-browser-text")}"
                data-conditional-errmsg="${msg("passkey-unsupported-browser-text")}">${msg("webauthn-doAuthenticate")}</button>
        <script type="module" src="${url.resourcesPath}/js/rasputin-passkeys.js"></script>
    </#if>
</#macro>
