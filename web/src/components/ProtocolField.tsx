import { Pause, Play } from "lucide-react";
import { useEffect, useRef, useState } from "react";

type FieldNode = {
  x: number;
  y: number;
  baseX: number;
  baseY: number;
  radius: number;
  phase: number;
  speed: number;
  kind: "consumer" | "provider" | "settlement";
};

const palette = {
  consumer: "#43b8c2",
  provider: "#9ee46a",
  settlement: "#f06a4a",
};

function createNodes(width: number, height: number): FieldNode[] {
  const columns = Math.max(6, Math.floor(width / 150));
  const rows = Math.max(4, Math.floor(height / 135));
  const nodes: FieldNode[] = [];
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < columns; column += 1) {
      const index = row * columns + column;
      const x = ((column + 0.5 + (row % 2) * 0.32) / columns) * width;
      const y = ((row + 0.5) / rows) * height;
      nodes.push({
        x,
        y,
        baseX: x,
        baseY: y,
        radius: index % 11 === 0 ? 7 : index % 4 === 0 ? 4 : 2.5,
        phase: index * 0.73,
        speed: 0.45 + (index % 5) * 0.08,
        kind: index % 11 === 0 ? "settlement" : index % 3 === 0 ? "consumer" : "provider",
      });
    }
  }
  return nodes;
}

export function ProtocolField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pointerRef = useRef({ x: -10_000, y: -10_000 });
  const frameRef = useRef<number>(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d");
    if (!context) return;
    const target = canvas;
    const drawing = context;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let nodes: FieldNode[] = [];
    let width = 0;
    let height = 0;

    function resize() {
      const bounds = target.getBoundingClientRect();
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = Math.max(1, bounds.width);
      height = Math.max(1, bounds.height);
      target.width = Math.round(width * ratio);
      target.height = Math.round(height * ratio);
      drawing.setTransform(ratio, 0, 0, ratio, 0, 0);
      nodes = createNodes(width, height);
    }

    function draw(time = 0) {
      drawing.clearRect(0, 0, width, height);
      drawing.fillStyle = "#0d1512";
      drawing.fillRect(0, 0, width, height);

      const seconds = time / 1_000;
      for (const node of nodes) {
        if (!paused && !reducedMotion) {
          node.x = node.baseX + Math.cos(seconds * node.speed + node.phase) * 7;
          node.y = node.baseY + Math.sin(seconds * node.speed * 0.8 + node.phase) * 6;
        }
        const dx = pointerRef.current.x - node.x;
        const dy = pointerRef.current.y - node.y;
        const distance = Math.hypot(dx, dy);
        if (distance < 170 && distance > 0 && !paused && !reducedMotion) {
          node.x -= (dx / distance) * (1 - distance / 170) * 12;
          node.y -= (dy / distance) * (1 - distance / 170) * 12;
        }
      }

      for (let i = 0; i < nodes.length; i += 1) {
        for (let j = i + 1; j < nodes.length; j += 1) {
          const a = nodes[i];
          const b = nodes[j];
          const distance = Math.hypot(a.x - b.x, a.y - b.y);
          if (distance > 178) continue;
          drawing.beginPath();
          drawing.moveTo(a.x, a.y);
          drawing.lineTo(b.x, b.y);
          drawing.strokeStyle = `rgba(190, 220, 202, ${0.1 + (1 - distance / 178) * 0.24})`;
          drawing.lineWidth = a.kind === "settlement" || b.kind === "settlement" ? 1.5 : 1;
          drawing.stroke();
        }
      }

      for (const node of nodes) {
        drawing.beginPath();
        drawing.arc(node.x, node.y, node.radius + (node.kind === "settlement" ? 3 : 0), 0, Math.PI * 2);
        drawing.fillStyle = node.kind === "settlement" ? "rgba(240, 106, 74, 0.13)" : "rgba(158, 228, 106, 0.06)";
        drawing.fill();
        drawing.beginPath();
        drawing.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        drawing.fillStyle = palette[node.kind];
        drawing.fill();
      }

      if (!paused && !reducedMotion) frameRef.current = window.requestAnimationFrame(draw);
    }

    const observer = new ResizeObserver(() => {
      resize();
      if (paused || reducedMotion) draw();
    });
    observer.observe(target);
    resize();
    draw();
    return () => {
      observer.disconnect();
      window.cancelAnimationFrame(frameRef.current);
    };
  }, [paused]);

  function onPointerMove(event: React.PointerEvent<HTMLCanvasElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    pointerRef.current = { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
  }

  return (
    <div className="protocol-field">
      <canvas
        aria-hidden="true"
        ref={canvasRef}
        className="protocol-field__canvas"
        onPointerMove={onPointerMove}
        onPointerLeave={() => (pointerRef.current = { x: -10_000, y: -10_000 })}
      />
      <button
        className="protocol-field__control"
        type="button"
        onClick={() => setPaused((value) => !value)}
        aria-label={paused ? "Play network animation" : "Pause network animation"}
        title={paused ? "Play animation" : "Pause animation"}
      >
        {paused ? <Play size={16} /> : <Pause size={16} />}
      </button>
    </div>
  );
}
