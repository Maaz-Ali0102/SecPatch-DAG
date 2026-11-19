import { useRef, useState, type DragEvent, type FormEvent, type ReactNode } from "react";
import gsap from "gsap";
import { useGSAP } from "@gsap/react";

gsap.registerPlugin(useGSAP);
gsap.defaults({ ease: "power3.out", duration: 0.5 });
export { gsap, useGSAP };

export const reducedMotion = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Number that counts up from zero whenever its value changes. */
export function CountUp({ value, suffix = "" }: { value: number | string; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  useGSAP(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof value !== "number" || reducedMotion()) { el.textContent = `${value}${suffix}`; return; }
    const state = { v: 0 };
    el.textContent = `0${suffix}`;
    gsap.to(state, { v: value, duration: 0.9, ease: "power2.out", onUpdate: () => { el.textContent = `${Math.round(state.v)}${suffix}`; } });
  }, { dependencies: [value, suffix], revertOnUpdate: true });
  return <span ref={ref} aria-label={`${value}${suffix}`} />;
}

export function Stat({ label, value, suffix, note, tone = "" }: { label: string; value: number | string; suffix?: string; note?: string; tone?: string }) {
  return <div className={`stat ${tone}`}>
    <span className="stat-label">{label}</span>
    <strong className="stat-value"><CountUp value={value} suffix={suffix} /></strong>
    {note && <small>{note}</small>}
  </div>;
}

export function Chip({ tone = "neutral", children }: { tone?: "ok" | "warn" | "bad" | "info" | "neutral" | "accent"; children: ReactNode }) {
  return <span className={`chip ${tone}`}>{children}</span>;
}

export function PageHead({ title, lead, actions }: { title: string; lead?: ReactNode; actions?: ReactNode }) {
  return <div className="page-head">
    <div><h2>{title}</h2>{lead && <p>{lead}</p>}</div>
    {actions && <div className="page-actions">{actions}</div>}
  </div>;
}

export function Card({ title, meta, children, className = "", actions }: { title?: ReactNode; meta?: ReactNode; children: ReactNode; className?: string; actions?: ReactNode }) {
  return <section className={`card ${className}`}>
    {(title || meta || actions) && <header className="card-head">
      <div>{title && <h3>{title}</h3>}{meta && <span className="card-meta">{meta}</span>}</div>
      {actions && <div className="card-actions">{actions}</div>}
    </header>}
    {children}
  </section>;
}

export function Empty({ title, text, action }: { title: string; text?: string; action?: ReactNode }) {
  return <div className="empty">
    <svg viewBox="0 0 64 40" aria-hidden="true"><rect x="2" y="8" width="20" height="14" rx="3" /><rect x="42" y="2" width="20" height="14" rx="3" /><rect x="42" y="24" width="20" height="14" rx="3" /><path d="M22 15h10M32 15V9h10M32 15v16h10" /></svg>
    <h4>{title}</h4>{text && <p>{text}</p>}{action}
  </div>;
}

/** Click-or-drop JSON picker used for every import in the dashboard. */
export function FileDrop({ label, hint, onFile, disabled, compact }: { label: string; hint?: ReactNode; onFile: (file: File) => void; disabled?: boolean; compact?: boolean }) {
  const [over, setOver] = useState(false);
  const drop = (e: DragEvent<HTMLLabelElement>) => {
    e.preventDefault(); setOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file && !disabled) onFile(file);
  };
  return <label className={`filedrop ${over ? "over" : ""} ${compact ? "compact" : ""} ${disabled ? "disabled" : ""}`}
    onDragOver={(e) => { e.preventDefault(); if (!disabled) setOver(true); }} onDragLeave={() => setOver(false)} onDrop={drop}>
    <input type="file" accept=".json,application/json" disabled={disabled} onChange={(e) => { const file = e.target.files?.[0]; if (file) onFile(file); e.target.value = ""; }} />
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V4m0 0l-5 5m5-5l5 5M4 20h16" /></svg>
    <span><b>{label}</b>{hint && <small>{hint}</small>}</span>
  </label>;
}

/** Dialog with a short GSAP entrance and Escape to close. */
export function Modal({ title, onClose, children, onSubmit }: { title: string; onClose: () => void; children: ReactNode; onSubmit?: (e: FormEvent<HTMLFormElement>) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useGSAP(() => {
    if (reducedMotion()) return;
    gsap.from(".modal-backdrop-fill", { opacity: 0, duration: 0.25 });
    gsap.from(".modal", { y: 18, opacity: 0, scale: 0.98, duration: 0.4 });
  }, { scope: ref });
  const body = <>
    <header className="card-head"><h3>{title}</h3><button type="button" className="icon-btn" aria-label="Close" onClick={onClose}>×</button></header>
    {children}
  </>;
  return <div className="modal-backdrop" ref={ref} onKeyDown={(e) => e.key === "Escape" && onClose()}>
    <div className="modal-backdrop-fill" onClick={onClose} />
    {onSubmit ? <form className="modal" role="dialog" aria-label={title} onSubmit={onSubmit}>{body}</form>
      : <div className="modal" role="dialog" aria-label={title}>{body}</div>}
  </div>;
}

/** Horizontal bars that grow from the left when their values change. */
export function Bars({ rows, max, unit = "" }: { rows: Array<{ label: string; value: number; tone?: string; note?: string }>; max?: number; unit?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const top = Math.max(max ?? 0, ...rows.map((r) => r.value), 1);
  useGSAP(() => {
    if (reducedMotion()) return;
    gsap.from(".bar-fill", { scaleX: 0, transformOrigin: "left center", duration: 0.9, stagger: 0.08 });
  }, { scope: ref, dependencies: [rows.map((r) => r.value).join(","), top], revertOnUpdate: true });
  return <div className="bars" ref={ref}>
    {rows.map((row) => <div className="bar-row" key={row.label}>
      <span className="bar-label">{row.label}</span>
      <div className="bar-track"><i className={`bar-fill ${row.tone ?? ""}`} style={{ width: `${(row.value / top) * 100}%` }} /></div>
      <b className="bar-value">{row.value}{unit}</b>
      {row.note && <small className="bar-note">{row.note}</small>}
    </div>)}
  </div>;
}
