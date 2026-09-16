// Example file to demonstrate findings. Not used in production.

async function handler(req: { body: { text: string; email: string }; user: { name: string; plan: string } }) {
  const prompt = "Summarize: " + req.body.text;
  console.log("prompt", prompt, req.body.email);

  const messages = [{ role: "user", content: prompt }];
  const payload = { user: req.user, messages };

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages,
  });

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: JSON.stringify(payload) }],
  });
}
