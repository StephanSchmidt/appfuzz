// The list holds ids (as strings: they are 64-bit); each item is fetched by itself.
const list = document.getElementById('list');
const ids = await fetch('/api/items').then((r) => r.json());
for (const id of ids) {
  fetch('/api/items/' + id)
    .then((r) => (r.ok ? r.json() : null))
    .then((item) => {
      const li = document.createElement('li');
      li.textContent = item ? item.name : 'missing';
      list.append(li);
    });
}
