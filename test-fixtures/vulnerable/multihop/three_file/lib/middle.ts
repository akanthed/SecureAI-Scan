import { callLlm } from "./llmclient";

export async function middleware(userInput: string) {
  return callLlm(userInput);
}
