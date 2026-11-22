<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/template.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the Rasputin frame with the install name
  as plain text (never displayNameHtml) and a data-rasputin-theme marker; the message block
  announced with role="alert"; the import map, the session-polling modules, the once-link
  guard and the organization switch dropped; "Try another way" moved to js/rasputin-page.js;
  no locale menu and no positive tabindex; no head end tag, so Keycloak injects no inline
  script into a page it answers a POST with.
-->
<#import "footer.ftl" as loginFooter>
<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<#assign installName = (realm.displayName)!"">
<!DOCTYPE html>
<html class="${properties.kcHtmlClass!}" lang="${lang}">

<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
    </#if>
    <title>${msg("rasputinPageTitle", installName)}</title>
    <link rel="icon" href="${url.resourcesPath}/img/favicon.svg" type="image/svg+xml" />
    <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>
    <#if properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
            <script src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <script src="${url.resourcesPath}/js/menu-button-links.js" type="module"></script>
    <script src="${url.resourcesPath}/js/rasputin-page.js" type="module"></script>
    <#if scripts??>
        <#list scripts as script>
            <script src="${script}" type="text/javascript"></script>
        </#list>
    </#if>
<#--
  No end tag for head, which HTML allows (the body start tag closes it). Keycloak
  (BrowserHistoryHelper, 26.8.2) writes an inline history.replaceState script
  in front of the head end tag of a page it answers a POST with; with no tag it
  writes none, so these pages carry no inline script. The doors' script policy
  would block that script anyway. What it did: after a POST, the address bar
  showed the step's own address, so a reload re-rendered the step. Without
  it, a reload re-sends the form and shows the expired page, whose link
  continues where the person left off.
-->

<body class="${properties.kcBodyClass!} ${bodyClass}" data-page-id="login-${pageId}" data-rasputin-theme="rasputin">
<div class="${properties.kcLoginClass!}">
    <div id="kc-header" class="${properties.kcHeaderClass!}">
        <span class="rasp-brand-mark"><span class="rasp-icon rasp-icon-brand" aria-hidden="true"></span> ${msg("rasputinBrand")}</span>
        <span id="kc-header-wrapper" class="${properties.kcHeaderWrapperClass!}">${installName}</span>
    </div>
    <main class="${properties.kcFormCardClass!}">
        <header class="${properties.kcFormHeaderClass!}">
        <#if !(auth?has_content && auth.showUsername() && !auth.showResetCredentials())>
            <h1 id="kc-page-title"><#nested "header"></h1>
            <#if displayRequiredFields>
                <p class="rasp-hint"><span class="required">*</span> ${msg("requiredFields")}</p>
            </#if>
        <#else>
            <#nested "show-username">
            <h1 id="kc-page-title"><#nested "header"></h1>
            <div id="kc-username" class="${properties.kcFormGroupClass!}">
                <span id="kc-attempted-username">${auth.attemptedUsername}</span>
                <a id="reset-login" href="${url.loginRestartFlowUrl}" aria-label="${msg("restartLoginTooltip")}">
                    <span class="${properties.kcResetFlowIcon!}" aria-hidden="true"></span>
                    <span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
                </a>
            </div>
        </#if>
        </header>
        <div id="kc-content">
            <div id="kc-content-wrapper">
                <#-- App-initiated actions should not see warning messages about the need to complete the action during sign-in. -->
                <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
                    <div id="kc-feedback" role="alert" class="${properties.kcAlertClass!} rasp-alert-${message.type}">
                        <#if message.type = 'success'><span class="${properties.kcFeedbackSuccessIcon!}" aria-hidden="true"></span></#if>
                        <#if message.type = 'warning'><span class="${properties.kcFeedbackWarningIcon!}" aria-hidden="true"></span></#if>
                        <#if message.type = 'error'><span class="${properties.kcFeedbackErrorIcon!}" aria-hidden="true"></span></#if>
                        <#if message.type = 'info'><span class="${properties.kcFeedbackInfoIcon!}" aria-hidden="true"></span></#if>
                        <span class="${properties.kcAlertTitleClass!} kc-feedback-text">${message.summary}</span>
                    </div>
                </#if>

                <#nested "form">

                <#if auth?has_content && auth.showTryAnotherWayLink()>
                    <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post">
                        <div class="${properties.kcFormGroupClass!}">
                            <input type="hidden" name="tryAnotherWay" value="on"/>
                            <button type="button" id="try-another-way" class="rasp-link" data-rasputin-submit="kc-select-try-another-way-form">${msg("doTryAnotherWay")}</button>
                        </div>
                    </form>
                </#if>

                <#nested "socialProviders">

                <#if displayInfo>
                    <div id="kc-info" class="${properties.kcSignUpClass!}">
                        <div id="kc-info-wrapper" class="${properties.kcInfoAreaWrapperClass!}">
                            <#nested "info">
                        </div>
                    </div>
                </#if>
            </div>
        </div>

        <@loginFooter.content/>
    </main>
</div>
</body>
</html>
</#macro>
