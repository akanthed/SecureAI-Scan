// Safe: a Google Maps client is not an LLM — must produce zero findings.
// (Regression fixture: substring matching used to treat any "google.*" call
// as an LLM call.)
import { Client } from "@googlemaps/google-maps-services-js";

const googleMapsClient = new Client({});

export async function handler(req: { body: { address: string } }) {
  const result = await googleMapsClient.geocode({
    params: { address: req.body.address, key: process.env.MAPS_KEY! },
  });
  return result.data;
}
