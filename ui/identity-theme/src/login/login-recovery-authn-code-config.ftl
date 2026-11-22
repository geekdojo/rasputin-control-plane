<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/login-recovery-authn-code-config.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): leads with COPY and PRINT; the download is
  <install name>-recovery-codes.txt and its text names the person and the address and says to
  move the codes into a password manager or onto paper and delete the file; the inline script
  and onchange handler moved to js/rasputin-recovery-codes.js; no PatternFly markup.
-->
<#import "template.ftl" as layout>
<#import "password-commons.ftl" as passwordCommons>
<@layout.registrationLayout; section>

<#if section = "header">
    ${msg("recovery-code-config-header")}
<#elseif section = "form">
    <div id="rasputin-recovery-codes"
         data-install-name="${(realm.displayName)!""}"
         data-username="${(auth.attemptedUsername)!""}"
         data-file-intro="${msg("rasputinRecoveryFileIntro")}"
         data-file-advice="${msg("rasputinRecoveryFileAdvice")}">
        <div class="${properties.kcRecoveryCodesWarning!}">
            <p class="rasp-alert-text"><strong>${msg("recovery-code-config-warning-title")}</strong> ${msg("recovery-code-config-warning-message")}</p>
        </div>

        <ol id="kc-recovery-codes-list" class="${properties.kcRecoveryCodesList!}">
            <#list recoveryAuthnCodesConfigBean.generatedRecoveryAuthnCodesList as code>
                <li>${code[0..3]}-${code[4..7]}-${code[8..]}</li>
            </#list>
        </ol>

        <div class="${properties.kcRecoveryCodesActions!}">
            <button id="copyRecoveryCodes" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="button">${msg("recovery-codes-copy")}</button>
            <button id="printRecoveryCodes" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="button">${msg("recovery-codes-print")}</button>
            <button id="downloadRecoveryCodes" class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!}" type="button">${msg("recovery-codes-download")}</button>
        </div>
        <p class="rasp-hint">${msg("rasputinRecoveryCodesUse")}</p>

        <div class="${properties.kcFormOptionsClass!}">
            <input class="${properties.kcCheckInputClass!}" type="checkbox" id="kcRecoveryCodesConfirmationCheck" name="kcRecoveryCodesConfirmationCheck"/>
            <label for="kcRecoveryCodesConfirmationCheck">${msg("recovery-codes-confirmation-message")}</label>
        </div>

        <form action="${url.loginAction}" class="${properties.kcFormGroupClass!}" id="kc-recovery-codes-settings-form" method="post">
            <input type="hidden" name="generatedRecoveryAuthnCodes" value="${recoveryAuthnCodesConfigBean.generatedRecoveryAuthnCodesAsString}" />
            <input type="hidden" name="generatedAt" value="${recoveryAuthnCodesConfigBean.generatedAt?c}" />
            <input type="hidden" id="userLabel" name="userLabel" value="${msg("recovery-codes-label-default")}" />
            <@passwordCommons.logoutOtherSessions/>

            <#if isAppInitiatedAction??>
                <input type="submit"
                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                id="saveRecoveryAuthnCodesBtn" value="${msg("recovery-codes-action-complete")}"
                disabled
                />
                <button type="submit"
                    class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                    id="cancelRecoveryAuthnCodesBtn" name="cancel-aia" value="true">${msg("recovery-codes-action-cancel")}</button>
            <#else>
                <input type="submit"
                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                id="saveRecoveryAuthnCodesBtn" value="${msg("recovery-codes-action-complete")}"
                disabled
                />
            </#if>
        </form>
    </div>
    <script type="module" src="${url.resourcesPath}/js/rasputin-recovery-codes.js"></script>
</#if>
</@layout.registrationLayout>
