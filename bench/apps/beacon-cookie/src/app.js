// Counts the visit, with the cookies to tell visitors apart.
navigator.sendBeacon('https://stats.example.org/visit', JSON.stringify({ page: location.pathname, c: document.cookie }));
