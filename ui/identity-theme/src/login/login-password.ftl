<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-password.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the double-submit guard moved to
  js/rasputin-page.js; "Forgot your password?" from the client's reset attribute, as on the
  sign-in page; no positive tabindex; messages escaped, never ?no_esc.
-->
<#import "template.ftl" as layout>
<#assign homeDoor = ["rasputin-console", "rasputin-mesh", "rasputin-reset-home"]?seq_contains((client.clientId)!"")>
<#assign resetUrl = (realm.getAttribute(homeDoor?then("rasputin.reset-home-url", "rasputin.reset-app-url")))!"">
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('password'); section>
    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <form id="kc-form-login" data-rasputin-once="login" action="${url.loginAction}"
                      method="post">
                    <div class="${properties.kcFormGroupClass!}">
                        <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>
                        <div class="${properties.kcInputGroup!}" dir="ltr">
                            <input id="password" class="${properties.kcInputClass!}" name="password"
                                   type="password" autocomplete="current-password" autofocus
                                   aria-invalid="<#if messagesPerField.existsError('password')>true</#if>"
                            />
                            <button class="${properties.kcFormPasswordVisibilityButtonClass!}" type="button" aria-label="${msg('showPassword')}"
                                    aria-controls="password"  data-password-toggle
                                    data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}" data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                    data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                                <i class="${properties.kcFormPasswordVisibilityIconShow!}" aria-hidden="true"></i>
                            </button>
                        </div>
                        <#if messagesPerField.existsError('password')>
                            <span id="input-error-password" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${messagesPerField.get('password')}
                            </span>
                        </#if>
                    </div>

                    <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                    </div>
                </form>
                <#if resetUrl?has_content>
                    <p class="rasp-links"><a id="rasputin-forgot-password" href="${resetUrl}">${msg("doForgotPassword")}</a></p>
                </#if>
            </div>
        </div>
        <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
    </#if>

</@layout.registrationLayout>
