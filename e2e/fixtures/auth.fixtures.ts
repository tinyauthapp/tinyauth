import {expect, Page} from '@playwright/test';
import { OTP } from 'otplib';

export class LoginFixture {
    constructor(public readonly page: Page) {}

    async run(username: string, password: string) {
        await expect(this.page.getByText('Welcome back, please login')).toBeVisible();
        await this.page.getByLabel('Username').fill(username);
        await this.page.getByLabel('Password').fill(password);
        await this.page.getByRole('button', { name: 'Login' }).click();
    }

    async expectSuccess(username: string) {
        await expect(this.page.getByText(`You are currently logged in as ${username}.`)).toBeVisible()
    }
}

export class LogoutFixture {
    constructor(public readonly page: Page) {}

    async run() {
        await expect(this.page.getByText('Click the button below to logout.')).toBeVisible();
        await this.page.getByRole('button', { name: 'Logout' }).click();
    }

    async expectSuccess() {
        await expect(this.page.getByText('Welcome back, please login')).toBeVisible();
    }
}

export class TOTPFixture {
    constructor(public readonly page: Page) {}

    async run(secret: string) {
        await expect(this.page.getByText('Enter your TOTP code')).toBeVisible();
        const otp = new OTP();
        const token = await otp.generate({ secret });
        await this.page.getByPlaceholder('XXXXXX').fill(token);
        // we shouldn't need to click continue, it will auto submit
        // await this.page.getByRole('button', { name: 'Continue' }).click();
    }

    async expectSuccess(username: string) {
        await expect(this.page.getByText(`You are currently logged in as ${username}.`)).toBeVisible()
    }
}