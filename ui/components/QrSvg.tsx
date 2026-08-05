import { useMemo } from 'react';
import { qrcodegen } from '../lib/qrcodegen';

// QrSvg renders `text` as a QR code (inline SVG). Dark modules sit on a white
// tile with a quiet-zone border: QR scanners expect dark-on-light regardless of
// the page's dark theme, so the tile is always light. Pure client-side — the
// encoder is vendored (lib/vendor/qrcodegen.ts) and does no I/O. All dark
// modules are emitted as one <path> (crisp and compact at any scale).
export function QrSvg({
  text,
  size = 148,
  border = 3,
}: {
  text: string;
  size?: number;
  border?: number;
}) {
  const { path, dim } = useMemo(() => {
    const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
    let d = '';
    for (let y = 0; y < qr.size; y++) {
      for (let x = 0; x < qr.size; x++) {
        if (qr.getModule(x, y)) d += `M${x + border} ${y + border}h1v1h-1z`;
      }
    }
    return { path: d, dim: qr.size + border * 2 };
  }, [text, border]);

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      shapeRendering="crispEdges"
      role="img"
      aria-label="QR code to open this system on another device"
      style={{ display: 'block', borderRadius: 4 }}
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={path} fill="#0b1220" />
    </svg>
  );
}
