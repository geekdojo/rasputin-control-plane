<#--
  Copied from Keycloak 26.8.2, themes/src/main/resources/theme/base/login/delete-credential.ftl.
  Copyright Red Hat, Inc. and/or its affiliates and other contributors.
  Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
  Changed for Rasputin (geekdojo/geekdojo-brain#988): copy only, inside the Rasputin frame; the
  delete button uses the danger style.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("deleteCredentialTitle", credentialLabel)}
    <#elseif section = "form">
    <p id="kc-delete-text">
        ${msg("deleteCredentialMessage", credentialLabel)}
    </p>
    <form class="form-actions" action="${url.loginAction}" method="POST">
        <div class="${properties.kcFormButtonsClass!}">
            <input class="${properties.kcButtonClass!} rasp-btn-danger ${properties.kcButtonLargeClass!}" name="accept" id="kc-accept" type="submit" value="${msg("doConfirmDelete")}"/>
            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel-aia" value="${msg("doCancel")}" id="kc-decline" type="submit" />
        </div>
    </form>
    </#if>
</@layout.registrationLayout>
