<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/logout-confirm.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the double-submit guard moved to
  js/rasputin-page.js; no positive tabindex.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("logoutConfirmTitle")}
    <#elseif section = "form">
        <div id="kc-logout-confirm" class="content-area">
            <p class="instruction">${msg("logoutConfirmHeader")}</p>

            <form class="form-actions" action="${url.logoutConfirmAction}" data-rasputin-once="confirmLogout" method="POST">
                <input type="hidden" name="session_code" value="${logoutConfirm.code}">
                <div class="${properties.kcFormGroupClass!}">
                    <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                               name="confirmLogout" id="kc-logout" type="submit" value="${msg("doLogout")}"/>
                    </div>
                </div>
            </form>

            <div id="kc-info-message">
                <#if !logoutConfirm.skipLink && (client.baseUrl)?has_content>
                    <p><a href="${client.baseUrl}">${msg("backToApplication")}</a></p>
                </#if>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>
