// Loads the partner's widget code and runs it.
fetch('https://plugins.partner.example/widget.js')
  .then((r) => r.text())
  .then((code) => eval(code));
