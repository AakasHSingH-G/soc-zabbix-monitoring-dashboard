const apiRoot = `${window.location.origin}/api/decoy`;
const grid = document.getElementById('productGrid');
const catalogState = document.getElementById('catalogState');
let cartCount = 0;

function writeResult(id, message) {
  const element = document.getElementById(id);
  if (element) element.textContent = message;
}

async function requestJson(path, options) {
  const response = await fetch(`${apiRoot}${path}`, options);
  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }
  if (!response.ok) throw new Error(payload?.error || `Request failed (${response.status})`);
  return payload;
}

function isProductDetailPath() {
  return /^\/product\/[^/]+$/.test(window.location.pathname);
}

async function renderProductDetail() {
  const match = window.location.pathname.match(/^\/product\/([^/]+)$/);
  const main = document.querySelector('main');
  if (!match || !main) return false;

  main.innerHTML = '<section class="decoy-section"><p class="decoy-kicker">Product detail</p><p>Loading synthetic product...</p></section>';
  try {
    const { product } = await requestJson(`/products/${encodeURIComponent(match[1])}`);
    main.innerHTML = `<section class="decoy-section decoy-product-detail"><a href="/" class="decoy-kicker">Back to catalog</a><div class="decoy-product-art" aria-hidden="true"></div><p class="decoy-kicker">Synthetic catalog item</p><h1>${product.name}</h1><p>${product.description}</p><strong>$${(product.price_cents / 100).toFixed(2)}</strong><div><button class="decoy-button" id="detailAddButton" type="button">Add to cart</button><output id="detailResult"></output></div></section>`;
    document.getElementById('detailAddButton').addEventListener('click', async () => {
      try {
        await requestJson('/cart', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ product_id: product.id, quantity: 1 }) });
        writeResult('detailResult', 'Added to synthetic cart.');
      } catch (error) {
        writeResult('detailResult', 'Cart is temporarily unavailable.');
      }
    });
  } catch (error) {
    main.innerHTML = '<section class="decoy-section"><p class="decoy-kicker">Catalog</p><h1>Product unavailable</h1><p>This synthetic product does not exist.</p><a class="decoy-button" href="/">Return to catalog</a></section>';
  }
  return true;
}

function renderAdminView() {
  if (!window.location.pathname.startsWith('/admin')) return false;
  document.querySelector('main').innerHTML = `<section class="admin-console"><aside class="admin-sidebar"><div class="admin-mark">FIELDROOM<br><span>OPERATIONS</span></div><nav><a class="active" href="/admin">Overview</a><a href="/admin/products">Products</a><a href="/admin/orders">Orders</a><a href="/admin/users">Users</a><a href="/admin/categories">Categories</a><a href="/admin/coupons">Coupons</a><a href="/admin/reports">Reports</a><a href="/admin/logs">Security logs</a><a href="/admin/settings">Settings</a></nav></aside><div class="admin-main"><div class="admin-top"><div><span class="decoy-kicker">Synthetic control plane</span><h1>Operations overview</h1></div><span class="admin-status">● DECOY ONLINE</span></div><div class="admin-metrics"><div><span>Orders today</span><strong>24</strong><small>+12% synthetic volume</small></div><div><span>Catalog items</span><strong>3</strong><small>All demo inventory</small></div><div><span>Review queue</span><strong>7</strong><small>Awaiting operator</small></div><div><span>Security signals</span><strong>18</strong><small>Telemetry active</small></div></div><div class="admin-columns"><section class="admin-card"><div class="admin-card-head"><h2>Recent orders</h2><span>SIMULATED</span></div><table><thead><tr><th>Order</th><th>Customer</th><th>Status</th><th>Total</th></tr></thead><tbody><tr><td>DEMO-1042</td><td>Northstar Lab</td><td><b class="admin-pill green">Queued</b></td><td>$128.00</td></tr><tr><td>DEMO-1041</td><td>Field Test User</td><td><b class="admin-pill amber">Review</b></td><td>$86.00</td></tr><tr><td>DEMO-1040</td><td>Synthetic Buyer</td><td><b class="admin-pill blue">Packed</b></td><td>$42.00</td></tr></tbody></table></section><section class="admin-card admin-alert"><div class="admin-card-head"><h2>Detection note</h2><span>EVENT BRIDGE</span></div><p>Every admin page visit and control interaction is synthetic telemetry. No real users, payments, or records are connected.</p><button class="decoy-button" id="adminProbeButton" type="button">Test security event</button><output id="adminProbeResult"></output></section></div></div></section>`;
  document.getElementById('adminProbeButton').addEventListener('click', async () => {
    try {
      await requestJson('/admin/dashboard');
    } catch (error) {
      writeResult('adminProbeResult', error.message.includes('403') ? 'Probe recorded and denied.' : 'Telemetry unavailable.');
    }
  });
  return true;
}

async function loadProducts() {
  if (!grid || !catalogState) return;
  try {
    const { products } = await requestJson('/products');
    catalogState.textContent = `${products.length} synthetic products`;
    grid.innerHTML = products.map(product => `<article class="decoy-product"><div class="decoy-product-art" aria-hidden="true"></div><h3>${product.name}</h3><p>${product.description}</p><div class="decoy-product-foot"><strong>$${(product.price_cents / 100).toFixed(2)}</strong><button type="button" data-product="${product.id}">Add to cart</button></div></article>`).join('');
    grid.querySelectorAll('[data-product]').forEach(button => button.addEventListener('click', () => addToCart(button.dataset.product)));
  } catch (error) {
    catalogState.textContent = 'Unavailable';
    grid.innerHTML = '<p>The synthetic catalog is currently offline.</p>';
  }
}

async function addToCart(productId) {
  try {
    await requestJson('/cart', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ product_id: productId, quantity: 1 }) });
    cartCount += 1;
    document.getElementById('cartCount').textContent = cartCount;
  } catch (error) {
    writeResult('catalogState', 'Cart unavailable');
  }
}

if (renderAdminView()) {
} else if (isProductDetailPath()) {
  renderProductDetail();
} else {
  const checkoutForm = document.getElementById('checkoutForm');
  const loginForm = document.getElementById('loginForm');
  if (checkoutForm) checkoutForm.addEventListener('submit', async event => {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(event.currentTarget));
    try {
      await requestJson('/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      writeResult('checkoutResult', 'Recorded as a synthetic checkout. No payment was processed.');
    } catch (error) {
      writeResult('checkoutResult', 'Checkout telemetry is unavailable.');
    }
  });
  if (loginForm) loginForm.addEventListener('submit', async event => {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(event.currentTarget));
    try {
      await requestJson('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } catch (error) {
      writeResult('loginResult', error.message.includes('401') ? 'Access denied. Attempt recorded.' : 'Login telemetry is unavailable.');
    }
  });
  loadProducts();
}
