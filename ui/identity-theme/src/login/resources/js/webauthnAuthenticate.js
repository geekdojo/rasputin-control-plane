// Copied from Keycloak 26.8.2,
// themes/src/main/resources/theme/base/login/resources/js/webauthnAuthenticate.js.
// Copyright Red Hat, Inc. and/or its affiliates and other contributors.
// Licensed under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0).
// Changed for Rasputin (geekdojo/geekdojo-brain#988): rfc4648 is imported by its
// relative path, because base resolves the bare name through an inline import
// map, which the sign-in pages' script policy forbids.
import { base64url } from "../../../common/keycloak/vendor/rfc4648/rfc4648.js";

// singleton
let abortController = undefined;

export function signal() {
    if (abortController) {
        // abort the previous call
        const abortError = new Error("Cancelling pending WebAuthn call");
        abortError.name = "AbortError";
        abortController.abort(abortError);
    }

    abortController = new AbortController();
    return abortController.signal;
}

export async function authenticateByWebAuthn(input) {
    const allowCredentials = input.isUserIdentified ? getAllowCredentials() : [];
    try {
        const result = await doAuthenticate({ ...input, allowCredentials });
        if (result) returnSuccess(result);
    } catch (error) {
        returnFailure(error);
    }
}

/**
 * Reads the allowed credentials from the hidden authn_select form.
 * Exported so that passkeysConditionalAuth.js can use them as well.
 */
export function getAllowCredentials() {
    const allowCredentials = [];
    const authnUse = document.forms['authn_select']?.authn_use_chk;
    if (authnUse !== undefined) {
        if (authnUse.length === undefined) {
            allowCredentials.push({
                id: base64url.parse(authnUse.value, { loose: true }),
                type: 'public-key',
            });
        } else {
            authnUse.forEach((entry) =>
                allowCredentials.push({
                    id: base64url.parse(entry.value, { loose: true }),
                    type: 'public-key',
                }));
        }
    }
    return allowCredentials;
}

/**
 * Core function for navigator.credentials.get().
 * Exported so that passkeysConditionalAuth.js does not need its own copy.
 *
 * input: { challenge, userVerification, rpId, createTimeout, errmsg,
 *           allowCredentials?: PublicKeyCredentialDescriptor[],
 *           additionalOptions?: object  ← e.g. { mediation: "conditional" | "optional" | "required" | "silent" } }
 */
export function doAuthenticate(input) {
    // Check if WebAuthn is supported by this browser
    if (!window.PublicKeyCredential) {
        returnFailure("WebAuthnUnsupportedBrowser");
        return;
    }

    const publicKey = {
        rpId: input.rpId,
        challenge: base64url.parse(input.challenge, { loose: true }),
    };

    if (input.createTimeout !== 0) {
        publicKey.timeout = input.createTimeout * 1000;
    }

    if (input.allowCredentials !== undefined) {
        publicKey.allowCredentials = input.allowCredentials;
    }

    if (input.userVerification !== 'not specified') {
        publicKey.userVerification = input.userVerification;
    }

    return navigator.credentials.get({
        publicKey: publicKey,
        signal: signal(),
        ...input.additionalOptions,
    });
}

export function returnSuccess(result) {
    document.getElementById("clientDataJSON").value = base64url.stringify(new Uint8Array(result.response.clientDataJSON), { pad: false });
    document.getElementById("authenticatorData").value = base64url.stringify(new Uint8Array(result.response.authenticatorData), { pad: false });
    document.getElementById("signature").value = base64url.stringify(new Uint8Array(result.response.signature), { pad: false });
    document.getElementById("credentialId").value = result.id;
    if (result.response.userHandle) {
        document.getElementById("userHandle").value = base64url.stringify(new Uint8Array(result.response.userHandle), { pad: false });
    }
    const rememberMe = document.getElementById("rememberMe");
    if (rememberMe) {
        const rememberMeInput = document.createElement("input");
        rememberMeInput.type = "hidden";
        rememberMeInput.name = "rememberMe";
        rememberMeInput.value = rememberMe.checked ? "on" : "off";
        document.getElementById("webauth").appendChild(rememberMeInput);
    }
    document.getElementById("webauth").requestSubmit();
}

export function returnFailure(err) {
    document.getElementById("error").value = err;
    document.getElementById("webauth").requestSubmit();
}
