// Safe: ordinary web-app logging in a file with no LLM SDK.
// (Regression fixture: "response"/"output" identifiers used to trigger AI002.)
export async function handler(req: { url: string }) {
  const response = await fetch(req.url);
  console.log("response status", response.status);
  const output = await response.json();
  console.log("output received", Object.keys(output).length);
  return output;
}

// Safe: a secret-named value logged in a file with no LLM SDK at all.
// AI002's "secret" branch used to fire regardless of LLM context — a general
// secret-scanner check masquerading as an AI-specific rule, contradicting
// this project's own scope contract. Found scanning stripe/agent-toolkit's
// benchmarks/furever demo app (EditAccountButton.tsx): a React account-edit
// form logging a bcrypt-hashed password from an API response, zero LLM
// imports anywhere in the file.
import bcrypt from "bcryptjs";

export async function onSubmit(values: { email: string; password: string }) {
  const newPassword = bcrypt.hashSync(values.password, 8);
  const response = await fetch("/api/account_update", {
    method: "POST",
    body: JSON.stringify({ newEmail: values.email, newPassword }),
  });
  const { email: newEmail, password: returnedPassword } = await response.json();
  console.log("response ok", newEmail, returnedPassword);
}

// Safe: a "key"-named constant that is a validation prefix, not a secret
// value, logged in a file with no LLM SDK. Found scanning upstream/context7's
// packages/sdk/src/client.ts: `API_KEY_PREFIX` is a hardcoded, non-secret
// string ("ctx7sk") the SDK uses only to validate the shape of a caller's
// key, never the key itself.
const API_KEY_PREFIX = "ctx7sk";

export function validateKey(apiKey: string) {
  if (!apiKey.startsWith(API_KEY_PREFIX)) {
    console.warn(`API key should start with '${API_KEY_PREFIX}'`);
  }
}
