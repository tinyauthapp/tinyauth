import { test, expect } from '@playwright/test';
import {LoginFixture, LogoutFixture, TOTPFixture} from "../fixtures/auth.fixtures";

test('should be able to login', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    await page.goto('http://tinyauth.127.0.0.1.sslip.io');
    await loginFixture.run('user1', 'password')
    await loginFixture.expectSuccess('user1')
});

test('should fail to login with wrong credentials', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    await page.goto('http://tinyauth.127.0.0.1.sslip.io');
    await loginFixture.run('user27267', 'password')
    const toast = page.locator('[data-sonner-toast]').first();
    await expect(toast).toBeVisible();
    await expect(toast).toContainText('Failed to log in');
});


test('should be able to logout', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    await page.goto('http://tinyauth.127.0.0.1.sslip.io');
    await loginFixture.run('user1', 'password')
    await loginFixture.expectSuccess('user1')
    const logoutFixture = new LogoutFixture(page);
    await logoutFixture.run()
})

test('should be able to login with totp', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    const totpFixture = new TOTPFixture(page);
    await page.goto('http://tinyauth.127.0.0.1.sslip.io');
    await loginFixture.run('user3', 'password')
    await totpFixture.run('MVR4JQWNXYKNM6HHJEYEFP2O74QIIEJE')
    await loginFixture.expectSuccess('user3');
});

test('should fail to login with wrong totp', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    const totpFixture = new TOTPFixture(page);
    await page.goto('http://tinyauth.127.0.0.1.sslip.io');
    await loginFixture.run('user3', 'password')
    await totpFixture.run('VZVMOMQCBN24DJ5VRFAL5TJAZGBHXMN3')
    const toast = page.locator('[data-sonner-toast]').first();
    await expect(toast).toBeVisible();
    await expect(toast).toContainText('Failed to verify code');
});
