// Copied from Keycloak 26.8.2,
// themes/src/main/resources/theme/base/login/resources/js/webauthnRegister.js.
// Copyright Red Hat, Inc. and/or its affiliates and other contributors.
// Licensed under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0).
// Changed for Rasputin (geekdojo/geekdojo-brain#988): rfc4648 is imported by its
// relative path, because base resolves the bare name through an inline import
// map, which the sign-in pages' script policy forbids; the label is the
// in-page NAME field (initLabel), not a window.prompt.
import { base64url } from "../../../common/keycloak/vendor/rfc4648/rfc4648.js";

export async function registerByWebAuthn(input) {

    // Check if WebAuthn is supported by this browser
    if (!window.PublicKeyCredential) {
        returnFailure("WebAuthnUnsupportedBrowser");
        return;
    }

    const publicKey = {
        challenge: base64url.parse(input.challenge, {loose: true}),
        rp: {id: input.rpId, name: input.rpEntityName},
        user: {
            id: base64url.parse(input.userid, {loose: true}),
            name: input.username,
            displayName: input.username
        },
        pubKeyCredParams: getPubKeyCredParams(input.signatureAlgorithms),
    };

    if (input.attestationConveyancePreference !== 'not specified') {
        publicKey.attestation = input.attestationConveyancePreference;
    }

    const authenticatorSelection = {};
    let isAuthenticatorSelectionSpecified = false;

    if (input.authenticatorAttachment !== 'not specified') {
        authenticatorSelection.authenticatorAttachment = input.authenticatorAttachment;
        isAuthenticatorSelectionSpecified = true;
    }

    if (input.residentKey && input.residentKey !== 'not specified') {
        // residentKey is the current spec field and the source of truth. requireResidentKey is
        // deprecated but still set for older clients: it is true iff residentKey is 'required'.
        authenticatorSelection.residentKey = input.residentKey;
        authenticatorSelection.requireResidentKey = input.residentKey === 'required';
        isAuthenticatorSelectionSpecified = true;
    } else if (input.requireResidentKey !== 'not specified') {
        // fall back to the deprecated option when residentKey is not specified
        if (input.requireResidentKey === 'Yes') {
            authenticatorSelection.residentKey = 'required';
            authenticatorSelection.requireResidentKey = true;
        } else {
            authenticatorSelection.residentKey = 'discouraged';
            authenticatorSelection.requireResidentKey = false;
        }
        isAuthenticatorSelectionSpecified = true;
    }

    if (input.userVerificationRequirement !== 'not specified') {
        authenticatorSelection.userVerification = input.userVerificationRequirement;
        isAuthenticatorSelectionSpecified = true;
    }

    if (isAuthenticatorSelectionSpecified) {
        publicKey.authenticatorSelection = authenticatorSelection;
    }

    if (input.createTimeout !== 0) {
        publicKey.timeout = input.createTimeout * 1000;
    }

    const excludeCredentials = getExcludeCredentials(input.excludeCredentialIds);
    if (excludeCredentials.length > 0) {
        publicKey.excludeCredentials = excludeCredentials;
    }

    try {
        const result = await doRegister(publicKey);
        returnSuccess(result, input.initLabel);
    } catch (error) {
        returnFailure(error);
    }
}

function doRegister(publicKey) {
    return navigator.credentials.create({publicKey});
}

function getPubKeyCredParams(signatureAlgorithmsList) {
    const pubKeyCredParams = [];
    if (signatureAlgorithmsList.length === 0) {
        pubKeyCredParams.push({type: "public-key", alg: -7});
        return pubKeyCredParams;
    }

    for (const entry of signatureAlgorithmsList) {
        pubKeyCredParams.push({
            type: "public-key",
            alg: entry
        });
    }

    return pubKeyCredParams;
}

function getExcludeCredentials(excludeCredentialIds) {
    const excludeCredentials = [];
    if (excludeCredentialIds === "") {
        return excludeCredentials;
    }

    for (const entry of excludeCredentialIds.split(',')) {
        excludeCredentials.push({
            type: "public-key",
            id: base64url.parse(entry, {loose: true})
        });
    }

    return excludeCredentials;
}

function getTransportsAsString(transportsList) {
    if (!Array.isArray(transportsList)) {
        return "";
    }

    return transportsList.join();
}

function returnSuccess(result, initLabel) {
    document.getElementById("clientDataJSON").value = base64url.stringify(new Uint8Array(result.response.clientDataJSON), {pad: false});
    document.getElementById("attestationObject").value = base64url.stringify(new Uint8Array(result.response.attestationObject), {pad: false});
    document.getElementById("publicKeyCredentialId").value = base64url.stringify(new Uint8Array(result.rawId), {pad: false});

    if (typeof result.response.getTransports === "function") {
        const transports = result.response.getTransports();
        if (transports) {
            document.getElementById("transports").value = getTransportsAsString(transports);
        }
    } else {
        console.log("Your browser is not able to recognize supported transport media for the authenticator.");
    }

    if (result.authenticatorAttachment) {
        document.getElementById("authenticatorAttachment").value = result.authenticatorAttachment;
    }

    // Rasputin: the label comes from the page's NAME field (rasputin-webauthn.js
    // passes it as initLabel), not from a window.prompt.
    document.getElementById("authenticatorLabel").value = initLabel;

    document.getElementById("register").requestSubmit();
}

function returnFailure(err) {
    document.getElementById("error").value = err;
    document.getElementById("register").requestSubmit();
}
