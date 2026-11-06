// Hashes in the background, a share of every 100 ms, as a miner does.
let nonce = 0;
setInterval(() => {
  let h = nonce;
  for (let i = 0; i < 1000000; i++) h = (h * 31 + i) % 1000003;
  nonce = h;
}, 100);
