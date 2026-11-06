// Shows the first item; assumes there is one.
const items = await fetch('/api/items').then((r) => r.json());
document.getElementById('top').textContent = items[0].name.toUpperCase();
