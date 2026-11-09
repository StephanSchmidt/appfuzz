// Physical links and attribute changes invalidate live collection caches.
let links = 0, attributes = 0;
export function collectionLinksChanged() { links++; }
export function collectionAttributesChanged() { attributes++; }
export function collectionVersion(sensitive = false) { return sensitive ? links + attributes : links; }
