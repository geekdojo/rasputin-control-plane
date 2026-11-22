<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/frontchannel-logout.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): the inline readystatechange redirect moved
  to js/rasputin-frontchannel-logout.js, which follows the Continue link once the page is
  complete; each app's sign-out frame has a title.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("frontchannel-logout.title")}
    <#elseif section = "form">
        <p>${msg("frontchannel-logout.message")}</p>
        <ul>
        <#list logout.clients as client>
            <li>
                ${client.name}
                <iframe src="${client.frontChannelLogoutUrl}" title="${msg("rasputinSignOutFrame", client.name)}" hidden></iframe>
            </li>
        </#list>
        </ul>
        <#if logout.logoutRedirectUri?has_content>
            <a id="continue" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" href="${logout.logoutRedirectUri}" data-rasputin-logout-redirect>${msg("doContinue")}</a>
            <script type="module" src="${url.resourcesPath}/js/rasputin-frontchannel-logout.js"></script>
        </#if>
    </#if>
</@layout.registrationLayout>
