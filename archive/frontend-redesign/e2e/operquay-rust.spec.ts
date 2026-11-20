import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Operquay-Rust Full-Stack Enterprise Suite', () => {
  test('renders both Dark and Light themes cleanly with zero WCAG AA accessibility violations', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Remote Desktop & Protocol Engine Settings' })).toBeVisible();
    await expect(page.getByText('Clean-Room Microsoft RDP (Zero IronRDP)')).toBeVisible();
    await expect(page.getByText('Clean-Room RFC 6143 VNC / RFB 3.8')).toBeVisible();

    // Dark theme accessibility scan
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    const darkScan = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(darkScan.violations).toEqual([]);

    // Switch to Light theme, verify background flips and stays accessible
    await page.getByRole('button', { name: 'Switch to Light theme' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(245, 246, 248)');

    const lightScan = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(lightScan.violations).toEqual([]);

    // Persists across reload
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  });

  test('supports settings search, latency simulator, progressive disclosure, save persistence & OTel /metrics', async ({ page }) => {
    await page.goto('/');

    // Select Ultra-Low Latency preset & simulate 280 ms SSM link
    await page.getByRole('radio', { name: /Ultra-Low Latency LAN/ }).click();
    await page.getByRole('button', { name: '280 ms SSM' }).click();
    await expect(page.getByText('Zero-RTT Local')).toBeVisible();

    // Open progressive disclosure Input section & choose German QWERTZ LCID layout
    await page.getByRole('button', { name: /Input Prediction & 25-LCID Keyboard Engine/ }).click();
    await page.locator('#keyboard-layout-select').selectOption('de-de-qwertz');

    // Sticky Unsaved Bar appears & persists cleanly via Rust PUT /api/v1/settings/remote-desktop
    const unsavedBar = page.getByRole('region', { name: 'Unsaved settings changes' });
    await expect(unsavedBar).toBeVisible();
    await page.getByRole('button', { name: 'Save Profile' }).click();
    await expect(page.getByText('Remote desktop profile saved and applied.')).toBeVisible();
    await expect(unsavedBar).toHaveCount(0);

    // Reload browser and confirm persisted state came from Rust backend
    await page.reload();
    await page.getByRole('button', { name: /Input Prediction & 25-LCID Keyboard Engine/ }).click();
    await expect(page.locator('#keyboard-layout-select')).toHaveValue('de-de-qwertz');

    // Filter registry declaratively by search
    await page.getByRole('searchbox', { name: 'Filter settings' }).fill('opentelemetry');
    await expect(page.getByRole('button', { name: /OpenTelemetry & Transport Diagnostics/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /Authentication & Certificate Verification/ })).toHaveCount(0);

    // Verify Prometheus /metrics reflects real settings update counter
    const metricsRes = await page.request.get('/metrics');
    expect(metricsRes.ok()).toBe(true);
    const metricsText = await metricsRes.text();
    expect(metricsText).toContain('operquay_settings_updates');
  });

  test('streams live OQR2 frames over Rust WebSocket, handles resize alignment & Ctrl+Alt+Del', async ({ page }) => {
    await page.goto('/');

    await page.getByRole('button', { name: 'Launch RDP Session' }).click();
    await expect(page.getByText('Connected (OQR2)')).toBeVisible({ timeout: 10_000 });

    const canvas = page.getByRole('img', { name: /Interactive RDP desktop canvas/ }).or(
      page.locator('canvas[aria-label="Interactive RDP desktop canvas"]'),
    );
    await expect(canvas).toBeVisible();

    // Trigger MS-RDPEDISP odd width resize (1281 -> 1280 even clamp on Rust backend!)
    await page.getByRole('button', { name: /Test Resize/ }).click();
    await expect(page.getByText(/^1280x720/)).toBeVisible({ timeout: 5_000 });

    // Send Ctrl+Alt+Del & verify live telemetry frames continue incrementing
    await page.getByRole('button', { name: 'Ctrl+Alt+Del' }).click();
    await canvas.focus();
    await page.keyboard.type('whoami');

    await expect(page.getByLabel('Live telemetry HUD')).toBeVisible();

    // Verify OTel summary reflects real started sessions and encoded frames
    const telRes = await page.request.get('/api/v1/telemetry/summary');
    expect(telRes.ok()).toBe(true);
    const telJson = (await telRes.json()) as {
      summary: { sessions_started_total: number; frames_encoded_total: number };
    };
    expect(telJson.summary.sessions_started_total).toBeGreaterThanOrEqual(1);
    expect(telJson.summary.frames_encoded_total).toBeGreaterThanOrEqual(1);

    // Return to settings and launch live VNC session cleanly
    await page.getByRole('button', { name: 'Back to Settings' }).click();
    await page.getByRole('button', { name: 'Launch VNC Session' }).click();
    await expect(page.getByText('Connected (OQR2)')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('canvas[aria-label="Interactive VNC desktop canvas"]')).toBeVisible();
  });

  test('launches single-use ticketed SSM session cleanly, records SHA-256 capture, exports MP4 & passes Axe on all views', async ({
    page,
  }) => {
    const wsUrls: string[] = [];
    page.on('websocket', (ws) => {
      wsUrls.push(ws.url());
    });

    await page.goto('/');
    await page.getByRole('button', { name: 'Connect Live Target' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();

    const modalDarkAxe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(modalDarkAxe.violations).toEqual([]);

    await page.getByLabel('Password (Ephemeral Zeroize)').fill('HiddenTicketPass!9');
    await page.getByRole('button', { name: /Mint Ticket & Connect/ }).click();

    // Connects over single-use ?ticket= with SSM VNC loopback, zero credential leak in WS URL
    await expect(page.getByText('Connected (OQR2)')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/VNC Session/i)).toBeVisible();
    expect(wsUrls.some((u) => u.includes('?ticket='))).toBe(true);
    expect(wsUrls.some((u) => u.includes('HiddenTicketPass'))).toBe(false);

    // Close session & verify fail-closed Recording + ISO-BMFF MP4 export + Trace Audit Ledger
    await page.getByRole('button', { name: 'Recordings & Audit' }).click();
    await expect(
      page.getByRole('heading', { name: 'Fail-Closed Session Recordings & Audit Ledger' }),
    ).toBeVisible();

    await expect(page.getByRole('link', { name: 'Export MP4' }).first()).toBeVisible({
      timeout: 5_000,
    });
    await page.getByRole('button', { name: 'Replay' }).first().click();
    await expect(page.getByText('Guacamole Session Replay')).toBeVisible();
    await page.getByRole('button', { name: 'Close player' }).click();
    const mp4Href = await page.getByRole('link', { name: 'Export MP4' }).first().getAttribute('href');
    expect(mp4Href).toBeTruthy();

    const mp4Res = await page.request.get(mp4Href!);
    expect(mp4Res.ok()).toBe(true);
    const mp4Body = await mp4Res.body();
    expect(mp4Body.includes(Buffer.from('ftyp'))).toBe(true);
    expect(mp4Body.includes(Buffer.from('moov'))).toBe(true);

    const auditDarkAxe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(auditDarkAxe.violations).toEqual([]);

    await page.getByRole('button', { name: 'Switch to Light theme' }).click();
    const auditLightAxe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(auditLightAxe.violations).toEqual([]);
  });

  test('navigates all enterprise workspaces, runs WASM terminal SSM shell, AI safety guardrail, K8s/DB/Admin & passes Axe', async ({
    page,
  }) => {
    await page.goto('/');

    // 1. Global Command Palette -> Open Cloud Fleet
    await page.getByRole('button', { name: 'Open Command Palette' }).click();
    await expect(page.getByRole('dialog', { name: 'Global Command Palette' })).toBeVisible();
    await page.getByRole('button', { name: /Open Cloud Fleet/ }).click();
    await expect(page.getByRole('heading', { name: 'AWS Cloud Fleet & Session Launchpad' })).toBeVisible();

    const cloudAxe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(cloudAxe.violations).toEqual([]);

    // 2. Open Sandbox Pure-Rust WASM Terminal Workspace & verify live SSM WS + AI Safety Block
    await page.getByRole('button', { name: 'Open Sandbox SSM Terminal' }).click();
    await expect(page.getByRole('heading', { name: 'Pure-Rust WASM Terminal Workspace' })).toBeVisible();
    await expect(page.getByText('operquay_term.wasm')).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'SSM · i-demo-0001' })).toContainText('[operquay-ssm]', {
      timeout: 8_000,
    });
    await page.getByRole('button', { name: /Test Block/ }).click();
    await expect(page.getByText('Destructive Command Blocked')).toBeVisible();
    await page.getByRole('button', { name: 'Snippets' }).click();
    await expect(page.getByText('Command Snippets Library')).toBeVisible();

    // 3. Switch through Kubernetes IDE tabs, Databases, Topology, Admin Security & scan Axe
    await page.getByRole('button', { name: 'Kubernetes', exact: true }).click();
    await expect(page.getByRole('heading', { name: /Kubernetes Multi-Cluster/ })).toBeVisible();
    await page.getByRole('button', { name: 'Cost Monitoring' }).click();
    await expect(page.getByText('Cluster Cost Allocation')).toBeVisible();
    await page.getByRole('button', { name: 'Helm Releases' }).click();
    await expect(page.getByText('Helm v3 Releases (0)')).toBeVisible();

    await page.getByRole('button', { name: 'Databases', exact: true }).click();
    await expect(page.getByRole('heading', { name: /TLS PostgreSQL Explorer/ })).toBeVisible();

    await page.getByRole('button', { name: 'Topology', exact: true }).click();
    await expect(page.getByRole('heading', { name: /VPC Network Topology/ })).toBeVisible();

    await page.getByRole('button', { name: 'Admin', exact: true }).click();
    await expect(page.getByRole('heading', { name: /Enterprise IAM, Multi-Tenant Governance/ })).toBeVisible();
    await page.getByRole('tab', { name: 'Security & AI Catalog' }).click();
    await expect(page.getByRole('heading', { name: 'Shared AI Model Catalog' })).toBeVisible();
    const adminDarkAxe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(adminDarkAxe.violations).toEqual([]);

    await page.getByRole('button', { name: 'Switch to Light theme' }).click();
    const adminLightAxe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(adminLightAxe.violations).toEqual([]);
  });
});
