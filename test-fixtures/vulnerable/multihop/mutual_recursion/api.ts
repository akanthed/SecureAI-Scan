import { callA } from "./a";

export async function handler(req: { body: { input: string } }) {
  callA(req.body.input);
}
