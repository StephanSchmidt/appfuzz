import { validName } from './custom-name.js';
import { HTMLUnknownElement } from '../node_modules/linkedom/esm/html/unknown-element.js';
import { HTMLElement } from '../node_modules/linkedom/esm/html/element.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { SVGElement } from '../node_modules/linkedom/esm/svg/element.js';
import { DocumentFragment } from '../node_modules/linkedom/esm/interface/document-fragment.js';
import { HTMLClasses } from '../node_modules/linkedom/esm/shared/html-classes.js';
import { CUSTOM_ELEMENTS, UPGRADE, END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { initializeElement } from './element-internals.js';

const NativeProxy = Proxy, read = Reflect.get;
const object = Object.create, prototype = Object.getPrototypeOf;
export const additionalInterfaces = {
  HTMLTableSectionElement: class HTMLTableSectionElement extends HTMLElement {},
  HTMLTableColElement: class HTMLTableColElement extends HTMLElement {},
  HTMLDialogElement: class HTMLDialogElement extends HTMLElement {},
};
const interfaces = { ...HTMLClasses, ...additionalInterfaces }, builtins = new Map();
// Use the interface table rather than linkedom's partial registration map;
// the latter omits inert interfaces such as HTMLDivElement.
const tags = {
  Anchor:'a', Area:'area', Audio:'audio', Base:'base', Body:'body', BR:'br', Button:'button', Canvas:'canvas',
  DList:'dl', Data:'data', DataList:'datalist', Details:'details', Dialog:'dialog', Directory:'dir', Div:'div',
  Embed:'embed', FieldSet:'fieldset', Font:'font', Form:'form', Frame:'frame', FrameSet:'frameset',
  Head:'head', Heading:'h1 h2 h3 h4 h5 h6', HR:'hr', Html:'html', IFrame:'iframe', Image:'img image',
  Input:'input', Label:'label', Legend:'legend', LI:'li', Link:'link', Map:'map', Marquee:'marquee',
  Menu:'menu', Meta:'meta', Meter:'meter', Mod:'del ins', OList:'ol', Object:'object', OptGroup:'optgroup',
  Option:'option', Output:'output', Paragraph:'p', Param:'param', Picture:'picture', Pre:'pre listing xmp',
  Progress:'progress', Quote:'q blockquote', Script:'script', Select:'select', Slot:'slot', Source:'source',
  Span:'span', Style:'style', Table:'table', TableCaption:'caption', TableCell:'td th', TableCol:'col colgroup',
  TableRow:'tr', TableSection:'tbody thead tfoot', Template:'template', TextArea:'textarea', Time:'time',
  Title:'title', Track:'track', UList:'ul', Video:'video',
};
for (const [name, locals] of Object.entries(tags)) for (const local of locals.split(' ')) builtins.set(local, interfaces['HTML' + name + 'Element']);
const getBuiltin = builtins.get.bind(builtins);
const genericNames = new Set('abbr acronym address article aside b basefont bdi bdo big center cite code dd dfn dt em figcaption figure footer header hgroup i kbd main mark nav nobr noembed noframes noscript plaintext rb rp rt rtc ruby s samp search section small strike strong sub summary sup tt u var wbr'.split(' '));
const generic = genericNames.has.bind(genericNames);
export const builtinInterface = local => getBuiltin(local) || (generic(local) || validName(local) ? HTMLElement : HTMLUnknownElement);
export function createBareElement(owner, identity, is = null, failed = false) {
  const construction = new NativeProxy(object(prototype(owner)), { get(_target, key) {
    if (key === CUSTOM_ELEMENTS) return { active: false, registry: null };
    if (key === UPGRADE) return null;
    if (key === 'createDocumentFragment') return () => new DocumentFragment(owner);
    return read(owner, key, owner);
  } });
  const Class = identity.namespace === 'http://www.w3.org/1999/xhtml' ? (failed ? HTMLUnknownElement : builtinInterface(identity.local))
    : identity.namespace === 'http://www.w3.org/2000/svg' ? SVGElement : Element;
  const node = new Class(construction, identity.local);
  for (let current = node, stop = node[END][NEXT]; current !== stop; current = current[NEXT]) current.ownerDocument = owner;
  return initializeElement(node, identity, is);
}
