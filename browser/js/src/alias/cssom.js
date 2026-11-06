// A <style> element's sheet: rules are kept as text, which is what CSS-in-JS
// libraries need from insertRule. No layout reads them.
export const parse = () => ({
  cssRules: [],
  insertRule(rule, i = this.cssRules.length) {
    this.cssRules.splice(i, 0, { cssText: String(rule) });
    return i;
  },
  deleteRule(i) {
    this.cssRules.splice(i, 1);
  },
});
