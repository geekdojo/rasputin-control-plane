// The SAML auto-post, moved out of base's inline window.onload in
// saml-post-form.ftl (geekdojo/geekdojo-brain#988): once the page has
// loaded, submit form[data-rasputin-autosubmit] once.
const form = document.querySelector('form[data-rasputin-autosubmit]');
if (form instanceof HTMLFormElement) {
  let sent = false;
  const send = () => {
    if (sent) return;
    sent = true;
    form.submit();
  };
  if (document.readyState === 'complete') {
    send();
  } else {
    window.addEventListener('load', send, { once: true });
  }
}
