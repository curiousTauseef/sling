import { h, Component } from '/common/external/preact.js';
import '/common/external/material.js';

export const options = {};

function mdl() {
  return options.mdl || options.componentHandler || window.componentHandler;
}

const RIPPLE_CLASS = 'js-ripple-effect';

const MDL_PREFIX = s => MDL_NO_PREFIX[s] ? s : `mdl-${s}`;

const MDL_NO_PREFIX = { 'is-active': true };

let uidCounter = 1;

function uid() {
  return ++uidCounter;
}

function extend(base, props) {
  for (let i in props) if (props.hasOwnProperty(i)) base[i] = props[i];
  return base;
}

function setClass(attributes, value, append) {
  let cl = getClass(attributes);
  if (attributes.className) delete attributes.className;
  if (append) value = cl ? (cl + ' ' + value) : value;
  attributes.class = value;
}

function getClass(attributes) {
  return attributes.class || attributes.className;
}

let propMaps = {
  disabled({ attributes }) {
    if (attributes.hasOwnProperty('disabled') && !attributes.disabled) {
      attributes.disabled = null;
    }
  },
  badge({ attributes }) {
    attributes['data-badge'] = attributes.badge;
    delete attributes.badge;
    setClass(attributes, 'mdl-badge', true);
  },
  active({ attributes }) {
    if (attributes.active) {
      setClass(attributes, 'is-active', true);
    }
  },
  shadow({ attributes }) {
    let d = parseFloat(attributes.shadow)|0,
      c = getClass(attributes).replace(/\smdl-[^ ]+--shadow\b/g,'');
    setClass(attributes, c + (c ? ' ' : '') + `mdl-shadow--${d}dp`);
  }
};

export class MaterialComponent extends Component {
  constructor() {
    super();
    this.component = 'none';
    this.js = false;
    this.ripple = false;
    this.mdlClasses = null;
    this.upgradedBase = null;
  }

  mdlRender(props) {
    return h('div', props, props.children);
  }

  render(props, state) {
    let r = this.mdlRender(props, state);
    if (this.nodeName) r.nodeName = this.nodeName;
    if (!r.attributes) r.attributes = {};
    r.attributes.class = this.createMdlClasses(props).concat(r.attributes.class || [], r.attributes.className || []).join(' ');
    for (let i in propMaps) if (propMaps.hasOwnProperty(i)) {
      if (props.hasOwnProperty(i)) {
        propMaps[i](r);
      }
    }
    if (this.base && this.upgradedBase) {
      this.preserveMdlDom(this.base, r);
    }
    return r;
  }

  // Copy some transient properties back out of the DOM into VDOM prior to diffing so they don't get overwritten
  preserveMdlDom(base, r) {
    if (!base || !base.hasAttribute || !r) return;

    let c = base.childNodes,
      persist = [
        'mdl-js-ripple-effect--ignore-events',
        'mdl-js-ripple-effect',
        'is-upgraded',
        'is-dirty'
      ],
      v = base.getAttribute('data-upgraded'),
      a = r.attributes,
      cl = getClass(a) || '',
      foundRipple = false;

    if (!a) a = {};

    if (v) {
      a['data-upgraded'] = v;
      upgradeQueue.add(base);
    }

    if (base.hasAttribute('ink-enabled')) {
      if (!r.attributes) r.attributes = {};
      r.attributes['ink-enabled'] = 'true';
    }

    for (let i=0; i<persist.length; i++) {
      if (base.classList.contains(persist[i])) {
        if (typeof a.class==='string') {
          if (cl.indexOf(persist[i])===-1) {
            cl += ' ' + persist[i];
          }
        }
        else {
          (cl || (cl = {}))[persist[i]] = true;
        }
      }
    }

    setClass(a, cl);
  }

  createMdlClasses(props) {
    let name = this.component,
      c = [],
      mapping = this.propClassMapping || {},
      js = props.js!==false && (this.js || this.ripple);
    if (name) c.push(name);
    if (this.mdlClasses) c.push(...this.mdlClasses);
    if (this.ripple && props.ripple!==false) {
      c.push(RIPPLE_CLASS);
    }
    if (js) c.push(`js-${name}`);
    for (let i in props) {
      if (props.hasOwnProperty(i) && props[i]===true) {
        c.push(MDL_NO_PREFIX[i] ? i : (mapping[i] || `${name}--${i}`));
      }
    }
    return c.map(MDL_PREFIX);
  }

  componentDidMount() {
    if (this.base!==this.upgradedBase) {
      if (this.upgradedBase) {
        mdl().downgradeElements(this.upgradedBase);
      }
      this.upgradedBase = null;
      if (this.base && this.base.parentElement) {
        this.upgradedBase = this.base;
        mdl().upgradeElement(this.base);
      }
    }
  }

  componentWillUnmount() {
    if (this.upgradedBase) {
      mdl().downgradeElements(this.upgradedBase);
      this.upgradedBase = null;
    }
  }
}


let upgradeQueue = {
  items: [],
  add(base) {
    if (upgradeQueue.items.push(base)===1) {
      requestAnimationFrame(upgradeQueue.process);
      // setTimeout(upgradeQueue.process, 1);
    }
  },
  process() {
    // console.log(`upgrading ${upgradeQueue.items.length} items`);
    let p = upgradeQueue.items;
    for (let i=p.length; i--; ) {
      let el = p[i],
        v = el.getAttribute('data-upgraded'),
        u = v && v.split(',');
      if (!u) continue;
      for (let j=u.length; j--; ) {
        let c = u[j],
          a = c && el[c];
        if (a) {
          if (a.updateClasses_) {
            a.updateClasses_();
          }
          if (a.onFocus_ && a.input_ && a.input_.matches && a.input_.matches(':focus')) {
            a.onFocus_();
          }
        }
      }
    }
    p.length = 0;
  }
};



/**
 * @class Icon
 * @desc An Icon in the Material Icons font. Note that you must include the font, usually by Google Fonts
 * @param icon The icon to render. Can also be specified in the Icon text
 *
 * @example
 * <Icon icon="menu" />
 * @example
 * <Icon>menu</Icon>
 */
export class Icon extends MaterialComponent {
  mdlRender(props) {
    let c = getClass(props) || '',
      icon = String(props.icon || props.children).replace(/[ -]/g, '_');
    delete props.icon;
    delete props.className;
    if (typeof c==='string') {
      c = 'material-icons ' + c;
    }
    else {
      c['material-icons'] = true;
    }
    return h('i', Object.assign({}, props, { 'class': c }),  icon);
  }
}




/** @class Button
 *  @desc A material button
 *
 *  @example
 *  <Button onClick={this.handleClick}>Hello World</Button>
 *
 *  @param primary = false
 *  @param accent = false
 *  @param colored = false
 *  @param raised = false
 *  @param icon = false
 *  @param fab = false
 *  @param mini-fab = false
 *  @param disabled = false
 */
export class Button extends MaterialComponent {
  constructor() {
    super();
    this.component = 'button';
    this.nodeName = 'button';
    this.js = true;
    this.ripple = true;
  }
}






/**
 * @class Card
 * @desc Cards are how you represent blocks of infomation. From the Material Design Specifications: A card is a sheet of material that serves as an entry point to more detailed information.
 * TODO: example
 */
export class Card extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card';
  }
}

export class CardTitle extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card__title';
    this.propClassMapping = {expand: 'card--expand'};
  }
}

export class CardTitleText extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card__title-text';
    this.nodeName = 'h2';
  }
}

export class CardMedia extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card__media';
  }
}

export class CardText extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card__supporting-text';
  }
}

export class CardActions extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card__actions';
    // this.mdlClasses = ['card--border'];
  }
}

export class CardMenu extends MaterialComponent {
  constructor() {
    super();
    this.component = 'card__menu';
  }
}

extend(Card, {
  Title: CardTitle,
  TitleText: CardTitleText,
  Media: CardMedia,
  Text: CardText,
  Actions: CardActions,
  Menu: CardMenu
});



/** Dialogs */

export class Dialog extends MaterialComponent {
  constructor() {
    super();
    this.component = 'dialog';
    this.nodeName = 'dialog';
    this.show = () => { this.base.show(); }
    this.showModal = () => { this.base.showModal(); }
    this.close = () => { this.base.close && this.base.close(); }
  }
}

export class DialogTitle extends MaterialComponent {
  constructor() {
    super();
    this.component = 'dialog__title';
  }
}

export class DialogContent extends MaterialComponent {
  constructor() {
    super();
    this.component = 'dialog__content';
  }
}

export class DialogActions extends MaterialComponent {
  constructor() {
    super();
    this.component = 'dialog__actions';
  }
}

extend(Dialog, {
  Title: DialogTitle,
  Content: DialogContent,
  Actions: DialogActions
});




/** Layouts */

/**
 *  @class Layout
 *  @desc Use a layout to specify how your app will use some of material's aspects. Your app should reside in this component. If you want a fixed header, drawer, or tabs, specify them here.
 *  @param fixed-header = false
 *  @param fixed-drawer = false
 *  @param overlay-drawer-button = false
 *  @param fixed-tabs = false
 *
 *  @example
 *  <Layout fixed-header>
 *    <Layout.Header>
 *      ...
 *    </Layout.Header>
 *    ...
 *  </Layout>
 */
export class Layout extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout';
    this.js = true;
  }
}

/** @param waterfall = false
 *  @param scroll = false
 */
export class LayoutHeader extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__header';
    this.nodeName = 'header';
  }
}

export class LayoutHeaderRow extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__header-row';
  }
}

export class LayoutTitle extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout-title';
    this.nodeName = 'span';
  }
}

export class LayoutSpacer extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout-spacer';
  }
}

export class LayoutDrawer extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__drawer';
  }
}

export class LayoutContent extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__content';
    this.nodeName = 'main';
  }
}

export class LayoutTabBar extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__tab-bar';
    this.js = true;
    this.ripple = false;
  }
}

/** @param active */
export class LayoutTab extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__tab';
    this.nodeName = 'a';
  }
}

/** @param active */
export class LayoutTabPanel extends MaterialComponent {
  constructor() {
    super();
    this.component = 'layout__tab-panel';
  }

  mdlRender(props) {
    return h(
      'section',
      props,
      h('div', { 'class': 'page-content' }, props.children)
    );
  }
}

extend(Layout, {
  Header: LayoutHeader,
  HeaderRow: LayoutHeaderRow,
  Title: LayoutTitle,
  Spacer: LayoutSpacer,
  Drawer: LayoutDrawer,
  Content: LayoutContent,
  TabBar: LayoutTabBar,
  Tab: LayoutTab,
  TabPanel: LayoutTabPanel
});



/** @param large-screen-only = false */
export class Navigation extends MaterialComponent {
  constructor() {
    super();
    this.component = 'navigation';
    this.nodeName = 'nav';
    this.propClassMapping = {'large-screen-only': 'layout--large-screen-only'}
  }

  mdlRender(props, state) {
    let r = super.mdlRender(props, state);
    r.children.forEach( item => {
      if (!item) return item;
      let c = item.attributes && getClass(item.attributes) || '';
      if (!c.match(/\bmdl-navigation__link\b/g)) {
        if (!item.attributes) item.attributes = {};
        setClass(item.attributes, ' mdl-navigation__link', true);
      }
    });
    return r;
  }
}

export class NavigationLink extends MaterialComponent {
  constructor(...args) {
    super(...args);
    this.component = 'navigation__link';
    this.nodeName = 'a';
    this.handleClick = this.handleClick.bind(this);
  }

  handleClick(e) {
    let { route, href, onClick, onclick } = this.props;
    onClick = onClick || onclick;
    if (typeof onClick==='function' && onClick({ type: 'click', target: this })===false) {
    }
    else if (typeof route==='function') {
      route(href);
    }
    e.preventDefault();
    return false;
  }

  mdlRender({ children, ...props }, state) {
    return h(
      'a',
      Object.assign({}, props, { onclick: this.handleClick }),
      children
    );
  }
}

Navigation.Link = NavigationLink;




export class Tabs extends MaterialComponent {
  constructor() {
    super();
    this.component = 'tabs';
    this.js = true;
    this.ripple = false;
  }
}

export class TabBar extends MaterialComponent {
  constructor() {
    super();
    this.component = 'tabs__tab-bar';
  }
}

export class Tab extends MaterialComponent {
  constructor() {
    super();
    this.component = 'tabs__tab';
    this.nodeName = 'a';
  }
}

export class TabPanel extends MaterialComponent {
  constructor() {
    super();
    this.component = 'tabs__panel';
    this.nodeName = 'section';
  }
}

extend(Tabs, {
  TabBar,
  Bar: TabBar,
  Tab,
  TabPanel,
  Panel: TabPanel
});



export class MegaFooter extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mega-footer';
    this.nodeName = 'footer';
  }
}

export class MegaFooterMiddleSection extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mega-footer__middle-section';
  }
}

export class MegaFooterDropDownSection extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mega-footer__drop-down-section';
  }
}

export class MegaFooterHeading extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mega-footer__heading';
    this.nodeName = 'h1';
  }
}

export class MegaFooterLinkList extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mega-footer__link-list';
    this.nodeName = 'ul';
  }
}

export class MegaFooterBottomSection extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mega-footer__bottom-section';
  }
}

extend(MegaFooter, {
  MiddleSection: MegaFooterMiddleSection,
  DropDownSection: MegaFooterDropDownSection,
  Heading: MegaFooterHeading,
  LinkList: MegaFooterLinkList,
  BottomSection: MegaFooterBottomSection
});




export class MiniFooter extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mini-footer';
    this.nodeName = 'footer';
  }
}

export class MiniFooterLeftSection extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mini-footer__left-section';
  }
}

export class MiniFooterLinkList extends MaterialComponent {
  constructor() {
    super();
    this.component = 'mini-footer__link-list';
    this.nodeName = 'ul';
  }
}

extend(MiniFooter, {
  LeftSection: MiniFooterLeftSection,
  LinkList: MiniFooterLinkList
});




/** Responsive Grid
 *  @param no-spacing = false
 */
export class Grid extends MaterialComponent {
  constructor() {
    super();
    this.component = 'grid';
  }
}

export class Cell extends MaterialComponent {
  constructor() {
    super();
    this.component = 'cell';
  }
}

Grid.Cell = Cell;





/** @param indeterminate = false */
export class Progress extends MaterialComponent {
  constructor() {
    super();
    this.component = 'progress';
    this.js = true;
  }

  mdlRender(props) {
    return h(
      'div',
      props,
      h('div', { 'class': 'progressbar bar bar1' }),
      h('div', { 'class': 'bufferbar bar bar2' }),
      h('div', { 'class': 'auxbar bar bar3' })
    );
  }

  componentDidUpdate() {
    let api = this.base.MaterialProgress,
      p = this.props;
    if (p.progress) api.setProgress(p.progress);
    if (p.buffer) api.setBuffer(p.buffer);
  }
}





/** @param active = false
 *  @param single-color = false
 */
export class Spinner extends MaterialComponent {
  constructor() {
    super();
    this.component = 'spinner';
    this.js = true;
    // this.shouldComponentUpdate = () => false;
  }
}





/** @param bottom-left = true
 *  @param bottom-right = false
 *  @param top-left = false
 *  @param top-right = false
 */
export class Menu extends MaterialComponent {
  constructor() {
    super();
    this.component = 'menu';
    this.nodeName = 'ul';
    this.js = true;
    this.ripple = true;
  }
}

/** @param disabled = false */
export class MenuItem extends MaterialComponent {
  constructor() {
    super();
    this.component = 'menu__item';
    this.nodeName = 'li';
  }
}

Menu.Item = MenuItem;





/** @param min = 0
 *  @param max = 100
 *  @param value = 0
 *  @param tabindex = 0
 *  @param disabled = false
 */
export class Slider extends MaterialComponent {
  constructor() {
    super();
    this.component = 'slider';
    this.js = true;
  }

  mdlRender(props) {
    return h('input', Object.assign({ type: 'range', tabindex: '0' }, props));
  }
}




/** Snackbar
 */

export class Snackbar extends MaterialComponent {
  constructor() {
    super();
    this.component = 'snackbar';
    this.js = true;
  }

  mdlRender(props) {
    return h(
      'div',
      props,
      h(
        'div',
        { 'class': 'mdl-snackbar__text' },
        props.children
      ),
      h('button', { 'class': 'mdl-snackbar__action', type: 'button' })
    );
  }
}




/** @param checked = false
 *  @param disabled = false
 */
export class CheckBox extends MaterialComponent {
  constructor() {
    super();
    this.component = 'checkbox';
    this.js = true;
    this.ripple = true;
  }

  getValue() {
    return this.base.children[0].checked;
  }

  mdlRender(props) {
    let evt = {};
    for (let i in props) if (i.match(/^on[a-z]+$/gi)) {
      evt[i] = props[i];
      delete props[i];
    }
    return h(
      'label',
      props,
      h('input', Object.assign({ type: 'checkbox', 'class': 'mdl-checkbox__input', checked: props.checked, disabled: props.disabled }, evt)),
      h('span', { 'class': 'mdl-checkbox__label' }, props.children),
      h('span', { 'class': 'mdl-checkbox__focus-helper' }),
      h(
        'span',
        { 'class': 'mdl-checkbox__box-outline' },
        h('span', { 'class': 'mdl-checkbox__tick-outline' })
      )
    );
  }
}




/** @param name (required)
*  @param value (required)
*  @param checked = false
  *  @param disabled = false
 */
export class Radio extends MaterialComponent {
  constructor() {
    super();
    this.component = 'radio';
    this.js = true;
    this.ripple = true;
  }

  getValue() {
    return this.base.children[0].checked;
  }

  mdlRender(props) {
    return h(
      'label',
      props,
      h('input', { type: 'radio', 'class': 'mdl-radio__button', name: props.name, value: props.value, checked: props.checked, disabled: props.disabled }),
      h('span', { 'class': 'mdl-radio__label' }, props.children)
    );
  }
}




/** @param checked = false
 *  @param disabled = false
 */
export class IconToggle extends MaterialComponent {
  constructor() {
    super();
    this.component = 'icon-toggle';
    this.js = true;
    this.ripple = true;
  }

  getValue() {
    return this.base.children[0].checked;
  }

  mdlRender(props) {
    return h(
      'label',
      props,
      h('input', { type: 'checkbox', 'class': 'mdl-icon-toggle__input', checked: props.checked, disabled: props.disabled }),
      h(
        'span',
        { 'class': 'mdl-icon-toggle__label material-icons' },
        props.children
      )
    );
  }
}




/** @param checked = false
 *  @param disabled = false
 */
export class Switch extends MaterialComponent {
  constructor() {
    super();
    this.component = 'switch';
    this.nodeName = 'label';
    this.js = true;
    this.ripple = true;
  }

  shouldComponentUpdate({ checked }) {
    if (Boolean(checked)===Boolean(this.props.checked)) return false;
    return true;
  }

  getValue() {
    return this.base.children[0].checked;
  }

  mdlRender({ ...props }) {
    let evt = {};
    for (let i in props) if (i.match(/^on[a-z]+$/gi)) {
      evt[i] = props[i];
      delete props[i];
    }
    return h(
      'label',
      props,
      h('input', Object.assign({ type: 'checkbox', 'class': 'mdl-switch__input', checked: props.checked, disabled: props.disabled }, evt)),
      h(
        'span',
        { 'class': 'mdl-switch__label' },
        props.children
      ),
      h('div', { 'class': 'mdl-switch__track' }),
      h(
        'div',
        { 'class': 'mdl-switch__thumb' },
        h('span', { 'class': 'mdl-switch__focus-helper' })
      )
    );
  }
}




/** @param selectable = false */
export class Table extends MaterialComponent {
  constructor() {
    super();
    this.component = 'data-table';
    this.nodeName = 'table';
    this.js = true;
  }
}

/** @param non-numeric = false */
export class TableCell extends MaterialComponent {
  constructor() {
    super();
    this.component = 'data-table__cell';
    this.nodeName = 'td';
  }
}

Table.Cell = TableCell;


export class List extends MaterialComponent {
  constructor() {
    super();
    this.component = 'list';
    this.nodeName = 'ul';
  }
}

/** @param two-line = false
*  @param three-line = false
 */
export class ListItem extends MaterialComponent {
  constructor() {
    super();
    this.component = 'list__item';
    this.nodeName = 'li';
  }
}

List.Item = ListItem;


/** @param floating-label = false
*  @param multiline = false
*  @param expandable = false
*  @param errorMessage = null
*  @param icon (used with expandable)
 */
export class TextField extends MaterialComponent {
  constructor(...args) {
    super(...args);
    this.component = 'textfield';
    this.js = true;
    this.id = uid();
  }

  componentDidUpdate() {
    let input = this.base && this.base.querySelector && this.base.querySelector('input,textarea');
    if (input && input.value && input.value!==this.props.value) {
      input.value = this.props.value;
    }
    if (input && input.setCustomValidity) {
      input.setCustomValidity(this.props.errorMessage || "");
    }
  }

  mdlRender(props={}) {
    let id = props.id || this.id,
      errorMessage = props.errorMessage,
      p = extend({}, props);

    delete p.class;
    delete p.errorMessage;

    let field = h(
      'div',
      null,
      h('input', Object.assign({ type: 'text', 'class': 'mdl-textfield__input', id: id, value: '' }, p)),
      h(
        'label',
        { 'class': 'mdl-textfield__label', 'for': id },
        props.label || props.children
      ),
      errorMessage ? h(
        'span',
        { 'class': 'mdl-textfield__error' },
        errorMessage
      ) : null
    );
    if (props.multiline) {
      field.children[0].nodeName = 'textarea';
      // field.children[0].children = [props.value];
    }
    if (props.expandable===true) {
      (field.attributes = field.attributes || {}).class = 'mdl-textfield__expandable-holder';
      field = h(
        'div',
        null,
        h(
          'label',
          { 'class': 'mdl-button mdl-js-button mdl-button--icon', 'for': id },
          h(
            'i',
            { 'class': 'material-icons' },
            props.icon
          )
        ),
        field
      );
    }
    let cl = getClass(props);
    if (cl) {
      (field.attributes = field.attributes || {}).class = cl;
    }

    return field;
  }
}






/** @param for [id]
 *  @param large = false
 */
export class Tooltip extends MaterialComponent {
  constructor() {
    super();
    this.component = 'tooltip';
  }
}




export default {
  options,
  Icon,
  Button,
  Card,
  Dialog,
  Layout,
  Navigation,
  Tabs,
  MegaFooter,
  MiniFooter,
  Grid,
  Cell,
  Progress,
  Spinner,
  Menu,
  Slider,
  Snackbar,
  CheckBox,
  Radio,
  IconToggle,
  Switch,
  Table,
  TextField,
  Tooltip,
  List,
  ListItem
};