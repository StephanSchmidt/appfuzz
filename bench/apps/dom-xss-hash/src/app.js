// Greets the visitor by the name after the # in the link.
const name = decodeURIComponent(location.hash.slice(1)) || 'guest';
document.getElementById('greeting').innerHTML = 'Hello, ' + name + '!';
