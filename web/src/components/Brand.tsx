import { Waypoints } from "lucide-react";
import { Link } from "react-router-dom";

interface BrandProps {
  compact?: boolean;
  inverted?: boolean;
}

export function Brand({ compact = false, inverted = false }: BrandProps) {
  return (
    <Link
      className={`brand${inverted ? " brand--inverted" : ""}`}
      to="/"
      aria-label="MycoMesh home"
    >
      <span className="brand__mark" aria-hidden="true">
        <Waypoints size={20} strokeWidth={2.25} />
      </span>
      {!compact && <span className="brand__name">MycoMesh</span>}
    </Link>
  );
}
