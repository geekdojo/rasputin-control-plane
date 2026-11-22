// The sign-in pages' shared behaviours, moved out of Keycloak's inline
// handlers into a file so the doors' script policy can hold
// (geekdojo/geekdojo-brain#988, ui.md §4.1). Every page loads it from
// template.ftl. It runs on clicks and submits only: no timer, no polling.
//
//   - form[data-rasputin-once="<name>"]: on submit, disables the form's
//     control of that name, as base's onsubmit="login.disabled = true" did,
//     so a double click sends one request.
//   - [data-rasputin-submit="<form id>"]: a click submits that form ("Try
//     another way"; base's onclick on template.ftl).
//   - [data-rasputin-retry]: a click fills the WebAuthn error page's
//     isSetRetry and executionValue fields and submits its form (base's
//     refreshPage() on webauthn-error.ftl).

document.addEventListener('submit', (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.hasAttribute('data-rasputin-once')) {
    return;
  }
  const control = form.elements.namedItem(form.dataset.rasputinOnce || 'login');
  if (control && 'disabled' in control) {
    control.disabled = true;
  }
});

document.addEventListener('click', (event) => {
  const target = event.target instanceof Element ? event.target : null;
  const submitter = target && target.closest('[data-rasputin-submit]');
  if (submitter) {
    event.preventDefault();
    const form = document.getElementById(submitter.getAttribute('data-rasputin-submit'));
    if (form instanceof HTMLFormElement) {
      form.requestSubmit();
    }
    return;
  }
  const retry = target && target.closest('[data-rasputin-retry]');
  if (retry) {
    event.preventDefault();
    const form = document.getElementById('kc-error-credential-form');
    const isSetRetry = document.getElementById('isSetRetry');
    const execution = document.getElementById('executionValue');
    if (form instanceof HTMLFormElement && isSetRetry && execution) {
      isSetRetry.value = 'retry';
      execution.value = retry.getAttribute('data-execution') || '';
      form.requestSubmit();
    }
  }
});
