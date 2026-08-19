import {expect, test} from '@playwright/test';
import {LoginFixture} from "../fixtures/auth.fixtures";

test('should be able to login to app with forward-auth', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    await page.goto('http://whoami.127.0.0.1.sslip.io');
    // redirect to tinyauth
    await expect(page.getByText('Welcome back, please login')).toBeVisible()
    await loginFixture.run('user1', 'password')
    // redirect to app
    await expect(page.getByText('whoami.127.0.0.1.sslip.io')).toBeVisible()
});

test('non authorized user should not be able to access app', async ({ page }) => {
    const loginFixture = new LoginFixture(page);
    await page.goto('http://whoami.127.0.0.1.sslip.io');
    // redirect to tinyauth
    await expect(page.getByText('Welcome back, please login')).toBeVisible()
    // user2 is not authorized to access app
    await loginFixture.run('user2', 'password')
    // redirect to app
    await expect(page.getByText('The user with username user2 is not authorized to access the resource whoami.')).toBeVisible()
})

test('allowed path should skip authentication', async ({ page }) => {
    await page.goto('http://whoami.127.0.0.1.sslip.io/foo');
    await expect(page.getByText('whoami.127.0.0.1.sslip.io')).toBeVisible()
})