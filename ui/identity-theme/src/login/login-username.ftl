<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-username.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the double-submit guard moved to
  js/rasputin-page.js; the heading names the install; no "Create an account" or identity-
  provider buttons here (the sign-in page alone offers registration, for the console; the realm
  has no identity provider); no positive tabindex; messages escaped, never ?no_esc.
-->
<#import "template.ftl" as layout>
<#import "passkeys.ftl" as passkeys>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username'); section>
    <#if section = "header">
        ${msg("rasputinSignInTo", (realm.displayName)!"")}
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <#if realm.password>
                    <form id="kc-form-login" data-rasputin-once="login" action="${url.loginAction}"
                          method="post">
                        <#if !usernameHidden??>
                            <div class="${properties.kcFormGroupClass!}">
                                <label for="username"
                                       class="${properties.kcLabelClass!}"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>

                                <input id="username"
                                       aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                                       class="${properties.kcInputClass!}" name="username"
                                       value="${(login.username!'')}"
                                       type="text" autofocus
                                       autocomplete="${(enableWebAuthnConditionalUI?has_content)?then('username webauthn', 'username')}"
                                       dir="ltr"/>

                                <#if messagesPerField.existsError('username')>
                                    <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                        ${messagesPerField.get('username')}
                                    </span>
                                </#if>
                            </div>
                        </#if>

                        <#if realm.rememberMe && !usernameHidden??>
                            <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                                <div id="kc-form-options">
                                    <div class="checkbox">
                                        <label>
                                            <input id="rememberMe" name="rememberMe" type="checkbox" <#if login.rememberMe??>checked</#if>> ${msg("rememberMe")}
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </#if>

                        <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                   name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                        </div>
                    </form>
                </#if>
            </div>
        </div>
        <@passkeys.conditionalUIData />
    </#if>

</@layout.registrationLayout>
