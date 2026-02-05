import type { Project, SourceFile } from "ts-morph";

export type Severity = "low" | "medium" | "high" | "critical";

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
