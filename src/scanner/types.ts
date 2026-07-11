import type { Project, SourceFile } from "ts-morph";

export type Severity = "low" | "medium" | "high" | "critical";

/**
 * Evidence tier — how the finding was established.
 *
 *  - "proven":    import-resolved sink + traced dataflow, or a parsed config
 *                 fact. The scanner can show the exact path.
 *  - "likely":    resolved sink or strong structural signal, but one hop of
 *                 the chain is heuristic (e.g. a name-based source).
 *  - "heuristic": pattern/proximity match only. Hidden by default; shown
 *                 with --paranoid.
 */
export type Evidence = "proven" | "likely" | "heuristic";

export interface TraceStep {
  kind: "source" | "flow" | "sink";
  file: string;
  line: number;
  note: string;
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  summary: string;
  description: string;
  recommendation: string;
  confidence: number;
  evidence: Evidence;
  /** Source → flow → sink steps proving the finding, when available. */
  trace?: TraceStep[];
}

export interface RuleContext {
  project: Project;
  sourceFiles: SourceFile[];
  rootPath: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  run(context: RuleContext): Finding[];
}
