'use client';

// Ported from the Figma "Cluster Node Management Interface" (commit 410f9da) —
// an animated HUD overlay: 48px grid, diagonal accent lines, three horizontal
// scan lines, pulsing radial orbs, animated corner brackets, drifting particles,
// and a radial vignette.
//
// EXEMPT from the Pantone 172 C accent remap that the rest of the UI uses.
// HUD chrome stays in the source cyan triplets (the classic "ambient cool /
// accent warm" pattern); an all-orange wash crushed contrast against the
// orange-dominant foreground chrome. Three cyans, matching the Figma exactly:
//   HUD_CYAN_PRIMARY    rgb(0, 200, 255)  grid, scan lines, corner brackets
//   HUD_CYAN_MID        rgb(0, 180, 255)  diagonals, radial orbs
//   HUD_CYAN_PARTICLE   rgb(0, 210, 255)  drifting particles
// If you tune these later, edit them here — don't reach for ACCENT_RGB.
//
// Canvas is position:fixed, pointerEvents:none, zIndex:0 — drop it once in the
// authed layout and wrap real chrome in zIndex:1 containers so it stays behind.

import { useEffect, useRef } from 'react';
import { useTheme } from '../lib/theme';
import { THEME_HUD } from './ui-theme';

export function HudBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { theme } = useTheme();

  useEffect(() => {
    // Canvas can't read --rasp-* CSS vars, so the HUD palette is keyed by
    // theme name in JS. Default keeps the source cyans; cyberdeck swaps to
    // amber so the grid/particles read as warm CRT phosphor.
    const { primary: HUD_CYAN_PRIMARY, mid: HUD_CYAN_MID, particle: HUD_CYAN_PARTICLE } =
      THEME_HUD[theme];

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animFrame = 0;
    let tick = 0;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    // Particles — count and motion mirror the Figma source.
    const particles = Array.from({ length: 40 }, () => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.5 + 0.2,
    }));

    // Corner brackets — normalized [0..1] positions, sx/sy give the L direction.
    const corners = [
      { x: 0.02, y: 0.04, sx: 1, sy: 1 },
      { x: 0.98, y: 0.04, sx: -1, sy: 1 },
      { x: 0.02, y: 0.96, sx: 1, sy: -1 },
      { x: 0.98, y: 0.96, sx: -1, sy: -1 },
    ];

    const draw = () => {
      const W = canvas.width;
      const H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      // — Grid —
      ctx.save();
      ctx.strokeStyle = `rgba(${HUD_CYAN_PRIMARY}, 0.045)`;
      ctx.lineWidth = 1;
      const cellSize = 48;
      for (let x = 0; x < W; x += cellSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, H);
        ctx.stroke();
      }
      for (let y = 0; y < H; y += cellSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(W, y);
        ctx.stroke();
      }
      ctx.restore();

      // — Diagonal accent lines —
      ctx.save();
      ctx.strokeStyle = `rgba(${HUD_CYAN_MID}, 0.06)`;
      ctx.lineWidth = 1;
      const diagSpacing = 120;
      for (let i = -H; i < W + H; i += diagSpacing) {
        ctx.beginPath();
        ctx.moveTo(i, 0);
        ctx.lineTo(i + H * 0.4, H);
        ctx.stroke();
      }
      ctx.restore();

      // — Horizontal accent lines (faded at the edges) —
      const hLines = [0.25, 0.5, 0.75];
      ctx.save();
      for (const f of hLines) {
        const y = H * f;
        const grad = ctx.createLinearGradient(0, 0, W, 0);
        grad.addColorStop(0, `rgba(${HUD_CYAN_PRIMARY}, 0)`);
        grad.addColorStop(0.2, `rgba(${HUD_CYAN_PRIMARY}, 0.08)`);
        grad.addColorStop(0.8, `rgba(${HUD_CYAN_PRIMARY}, 0.08)`);
        grad.addColorStop(1, `rgba(${HUD_CYAN_PRIMARY}, 0)`);
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(W, y);
        ctx.stroke();
      }
      ctx.restore();

      // — Glowing radial orbs (three, each on its own pulse phase) —
      const orbPositions = [
        { x: W * 0.15, y: H * 0.3, pulse: 0 },
        { x: W * 0.82, y: H * 0.65, pulse: 1.5 },
        { x: W * 0.5, y: H * 0.8, pulse: 3 },
      ];
      for (const orb of orbPositions) {
        const alpha = 0.04 + 0.02 * Math.sin(tick * 0.02 + orb.pulse);
        const r = 120 + 20 * Math.sin(tick * 0.015 + orb.pulse);
        const g = ctx.createRadialGradient(orb.x, orb.y, 0, orb.x, orb.y, r);
        g.addColorStop(0, `rgba(${HUD_CYAN_MID}, ${alpha * 3})`);
        g.addColorStop(1, `rgba(${HUD_CYAN_MID}, 0)`);
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(orb.x, orb.y, r, 0, Math.PI * 2);
        ctx.fill();
      }

      // — Corner brackets (subtle breathing) —
      ctx.save();
      ctx.strokeStyle = `rgba(${HUD_CYAN_PRIMARY}, ${0.25 + 0.05 * Math.sin(tick * 0.04)})`;
      ctx.lineWidth = 1.5;
      const bSize = 28;
      for (const c of corners) {
        const cx = W * c.x;
        const cy = H * c.y;
        ctx.beginPath();
        ctx.moveTo(cx + c.sx * bSize, cy);
        ctx.lineTo(cx, cy);
        ctx.lineTo(cx, cy + c.sy * bSize);
        ctx.stroke();
      }
      ctx.restore();

      // — Floating particles (wrap on viewport edge) —
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = W;
        if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H;
        if (p.y > H) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${HUD_CYAN_PARTICLE}, ${p.alpha * (0.7 + 0.3 * Math.sin(tick * 0.03 + p.x))})`;
        ctx.fill();
      }

      // — Vignette (preserves the dark navy bg around the edges) —
      const vig = ctx.createRadialGradient(W / 2, H / 2, H * 0.3, W / 2, H / 2, H * 0.85);
      vig.addColorStop(0, 'rgba(0,0,0,0)');
      vig.addColorStop(1, 'rgba(0,0,0,0.45)');
      ctx.fillStyle = vig;
      ctx.fillRect(0, 0, W, H);

      tick++;
      animFrame = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animFrame);
      window.removeEventListener('resize', resize);
    };
  }, [theme]); // restart the animation with the new palette when the theme changes

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      style={{
        position: 'fixed',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
      }}
    />
  );
}
