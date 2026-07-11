// Safe: ordinary web-app logging in a file with no LLM SDK.
// (Regression fixture: "response"/"output" identifiers used to trigger AI002.)
export async function handler(req: { url: string }) {
  const response = await fetch(req.url);
  console.log("response status", response.status);
  const output = await response.json();
  console.log("output received", Object.keys(output).length);
  return output;
}
