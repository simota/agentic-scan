// Seed a local server with demo items: node scripts/seed.js
const fetch = require("node-fetch");

async function main() {
  for (const name of ["Rice", "Beans", "Oats"]) {
    await fetch("http://localhost:5000/api/items", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, price_cents: 250 }),
    });
  }
}

main();
