<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): links chosen per client (ui.md §4.3) from
  the realm attributes rasputin.console-url, rasputin.reset-home-url and rasputin.reset-app-url,
  each left out when its attribute is absent; the heading names the install, or at the app door
  the app; the certificate-warning line; the double-submit guard moved to js/rasputin-page.js;
  no positive tabindex; identity-provider buttons dropped (the realm has none).
-->
<#import "template.ftl" as layout>
<#import "passkeys.ftl" as passkeys>
<#assign clientId = (client.clientId)!"">
<#assign homeDoor = ["rasputin-console", "rasputin-mesh", "rasputin-reset-home"]?seq_contains(clientId)>
<#assign consoleUrl = (realm.getAttribute("rasputin.console-url"))!"">
<#if homeDoor>
    <#assign resetUrl = (realm.getAttribute("rasputin.reset-home-url"))!"">
    <#assign headingName = (realm.displayName)!"">
<#else>
    <#assign resetUrl = (realm.getAttribute("rasputin.reset-app-url"))!"">
    <#assign headingName = (client.name)?has_content?then(client.name, (realm.displayName)!"")>
</#if>
<#assign offerRegister = clientId == "rasputin-console" && realm.password && realm.registrationAllowed && !registrationDisabled??>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=true; section>
    <#if section = "header">
        ${msg("rasputinSignInTo", headingName)}
    <#elseif section = "form">
        <div id="kc-form">
          <div id="kc-form-wrapper">
            <#if realm.password>
                <form id="kc-form-login" data-rasputin-once="login" action="${url.loginAction}" method="post">
                    <#if !usernameHidden??>
                        <div class="${properties.kcFormGroupClass!}">
                            <label for="username" class="${properties.kcLabelClass!}"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>

                            <input id="username" class="${properties.kcInputClass!}" name="username" value="${(login.username!'')}" type="text"
                                   autofocus autocomplete="${(enableWebAuthnConditionalUI?has_content)?then('username webauthn', 'username')}"
                                   aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                                   <#if messagesPerField.existsError('username','password')>aria-describedby="input-error"</#if>
                                   dir="ltr"
                            />

                            <#if messagesPerField.existsError('username','password')>
                                <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                    ${messagesPerField.getFirstError('username','password')}
                                </span>
                            </#if>
                        </div>
                    </#if>

                    <div class="${properties.kcFormGroupClass!}">
                        <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>

                        <div class="${properties.kcInputGroup!}" dir="ltr">
                            <input id="password" class="${properties.kcInputClass!}" name="password" type="password" autocomplete="current-password"
                                   aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                            />
                            <button class="${properties.kcFormPasswordVisibilityButtonClass!}" type="button" aria-label="${msg("showPassword")}"
                                    aria-controls="password" data-password-toggle
                                    data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}" data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                    data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                                <i class="${properties.kcFormPasswordVisibilityIconShow!}" aria-hidden="true"></i>
                            </button>
                        </div>

                        <#if usernameHidden?? && messagesPerField.existsError('username','password')>
                            <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${messagesPerField.getFirstError('username','password')}
                            </span>
                        </#if>
                    </div>

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
                        <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                    </div>
                </form>
            </#if>
          </div>
        </div>
        <@passkeys.conditionalUIData />
        <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
    <#elseif section = "info" >
        <div id="rasputin-links" class="rasp-links">
            <#if resetUrl?has_content>
                <a id="rasputin-forgot-password" href="${resetUrl}">${msg("doForgotPassword")}</a>
            </#if>
            <#if offerRegister>
                <a id="rasputin-register" href="${url.registrationUrl}">${msg("doRegister")}</a>
            </#if>
        </div>
        <#if clientId == "rasputin-console" && consoleUrl?has_content>
            <p id="rasputin-repair" class="rasp-hint">${msg("rasputinRepairLead")} <a href="${consoleUrl}/repair">${msg("rasputinRepairLink")}</a></p>
        </#if>
        <#if !homeDoor && consoleUrl?has_content>
            <p id="rasputin-create-at-home" class="rasp-hint">${msg("rasputinCreateAtHome", consoleUrl)}</p>
        </#if>
        <p id="rasputin-certificate-warning" class="rasp-hint">${msg("rasputinCertificateWarning")}</p>
    </#if>
</@layout.registrationLayout>
