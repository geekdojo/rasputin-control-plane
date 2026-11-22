<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-recovery-authn-code-input.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the double-submit guard moved to
  js/rasputin-page.js; no positive tabindex; messages escaped, never ?no_esc.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('recoveryCodeInput'); section>

    <#if section = "header">
        ${msg("auth-recovery-code-header")}
    <#elseif section = "form">
        <form id="kc-recovery-code-login-form" class="${properties.kcFormClass!}" data-rasputin-once="login" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="recoveryCodeInput" class="${properties.kcLabelClass!}">${msg("auth-recovery-code-prompt", recoveryAuthnCodesInputBean.codeNumber?c)}</label>
                </div>

                <div class="${properties.kcInputWrapperClass!}">
                    <input id="recoveryCodeInput"
                           name="recoveryCodeInput"
                           aria-invalid="<#if messagesPerField.existsError('recoveryCodeInput')>true</#if>"
                           autocomplete="one-time-code"
                           type="text"
                           class="${properties.kcInputClass!}"
                           inputmode="text"
                           autofocus
                           dir="ltr"/>

                    <#if messagesPerField.existsError('recoveryCodeInput')>
                        <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${messagesPerField.get('recoveryCodeInput')}
                        </span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input
                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                            name="login" id="kc-login" type="submit" value="${msg("doLogIn")}" />
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
