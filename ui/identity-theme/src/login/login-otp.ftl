<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-otp.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the double-submit guard moved to
  js/rasputin-page.js; no positive tabindex; messages escaped, never ?no_esc.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('totp'); section>
    <#if section="header">
        ${msg("loginOtpTitle")}
    <#elseif section="form">
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" data-rasputin-once="login" action="${url.loginAction}"
            method="post">
            <#if otpLogin.userOtpCredentials?size gt 1>
                <fieldset class="${properties.kcFormGroupClass!}">
                    <legend class="${properties.kcLabelClass!}">${msg("loginChooseAuthenticator")}</legend>
                    <#list otpLogin.userOtpCredentials as otpCredential>
                        <div class="${properties.kcLoginOTPListClass!}">
                            <input id="kc-otp-credential-${otpCredential?index}" class="${properties.kcLoginOTPListInputClass!}" type="radio" name="selectedCredentialId" value="${otpCredential.id}" <#if otpCredential.id == otpLogin.selectedCredentialId>checked="checked"</#if>>
                            <label for="kc-otp-credential-${otpCredential?index}" class="${properties.kcLoginOTPListItemHeaderClass!}">
                                <span class="${properties.kcLoginOTPListItemIconClass!}" aria-hidden="true"></span>
                                <span class="${properties.kcLoginOTPListItemTitleClass!}">${otpCredential.userLabel}</span>
                            </label>
                        </div>
                    </#list>
                </fieldset>
            </#if>

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="otp" class="${properties.kcLabelClass!}">${msg("loginOtpOneTime")}</label>
                </div>

                <div class="${properties.kcInputWrapperClass!}">
                    <input id="otp" name="otp" autocomplete="one-time-code" type="text" class="${properties.kcInputClass!}"
                           autofocus aria-invalid="<#if messagesPerField.existsError('totp')>true</#if>" inputmode="numeric"
                           dir="ltr" />

                    <#if messagesPerField.existsError('totp')>
                        <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}"
                              aria-live="polite">
                            ${messagesPerField.get('totp')}
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
