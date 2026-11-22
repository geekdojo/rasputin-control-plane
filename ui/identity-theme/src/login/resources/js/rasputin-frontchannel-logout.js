// The front-channel sign-out page's redirect, moved out of base's inline
// script in frontchannel-logout.ftl (geekdojo/geekdojo-brain#988): once the
// page and every app's sign-out frame have loaded, follow the page's own
// Continue link, as a person would. It waits on the document's own
// "complete", never a timer.
const link = document.querySelector('a[data-rasputin-logout-redirect]');
if (link instanceof HTMLAnchorElement) {
  const go = () => link.click();
  if (document.readyState === 'complete') {
    go();
  } else {
    document.addEventListener('readystatechange', () => {
      if (document.readyState === 'complete') go();
    });
  }
}
