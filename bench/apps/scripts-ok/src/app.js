// Lists the names the page put in window.app, as text.
const list = document.getElementById('list');
for (const name of window.app.names) {
  const li = document.createElement('li');
  li.textContent = name;
  list.append(li);
}
