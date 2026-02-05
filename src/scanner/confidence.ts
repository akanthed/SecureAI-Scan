export interface ConfidenceInputs {
  directUserInput?: boolean;
  stringConcatOrTemplate?: boolean;
  requestObjectSource?: boolean;
  confirmedLlmCall?: boolean;
}

export function calculateConfidence(inputs: ConfidenceInputs): number {
  let score = 0;
  if (inputs.directUserInput) {
    score += 0.3;
  }
  if (inputs.stringConcatOrTemplate) {
    score += 0.3;
  }
  if (inputs.requestObjectSource) {
    score += 0.2;
  }
  if (inputs.confirmedLlmCall) {
    score += 0.2;
  }
  return Math.min(1, Number(score.toFixed(2)));
}
