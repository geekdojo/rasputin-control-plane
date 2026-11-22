// The recovery-codes page, moved out of base's inline script and onchange
// handler in login-recovery-authn-code-config.ftl
// (geekdojo/geekdojo-brain#988, ui.md §4.3).
//
//   - COPY puts the codes on the clipboard.
//   - PRINT prints the page; the print style sheet shows only the codes.
//   - DOWNLOAD saves <install name>-recovery-codes.txt, whose text names the
//     person and the address and says to move the codes into a password
//     manager or onto paper and delete the file.
//   - Ticking "I have saved these codes" enables the save button, and
//     unticking disables it again.

/** The codes, one per line, as the page lists them. */
export function codesText(doc) {
  return Array.from(doc.querySelectorAll('#kc-recovery-codes-list li'))
    .map((li) => (li.textContent || '').replace(/\s+/g, ' ').trim())
    .join('\n');
}

/** The download's name and text. */
export function downloadFile(root, codes, address) {
  const d = root.dataset;
  const install = d.installName || 'Rasputin';
  const lines = [
    d.fileIntro.replace('{0}', d.username || '').replace('{1}', install).replace('{2}', address),
    '',
    codes,
    '',
    d.fileAdvice,
  ];
  return { name: `${install}-recovery-codes.txt`, text: lines.join('\n') + '\n' };
}

const root = document.getElementById('rasputin-recovery-codes');
if (root) {
  const save = document.getElementById('saveRecoveryAuthnCodesBtn');
  const check = document.getElementById('kcRecoveryCodesConfirmationCheck');
  if (check && save) {
    save.disabled = !check.checked;
    check.addEventListener('change', () => {
      save.disabled = !check.checked;
    });
  }
  document.getElementById('copyRecoveryCodes')?.addEventListener('click', () => {
    navigator.clipboard.writeText(codesText(document));
  });
  document.getElementById('printRecoveryCodes')?.addEventListener('click', () => {
    window.print();
  });
  document.getElementById('downloadRecoveryCodes')?.addEventListener('click', () => {
    const file = downloadFile(root, codesText(document), window.location.origin);
    const a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(file.text);
    a.download = file.name;
    a.hidden = true;
    document.body.appendChild(a);
    a.click();
    a.remove();
  });
}
