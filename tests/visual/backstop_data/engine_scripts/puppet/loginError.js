/**
 * BackstopJS - Login Error State Script
 * Triggers validation error state on login form
 */

module.exports = async (page, _scenario, _vp) => {
  // Wait for form to be ready
  await page.waitForSelector('form');

  // Fill in invalid email
  const emailInput = await page.$('input[type="email"], input[name="email"]');
  if (emailInput) {
    await emailInput.type('invalid');
  }

  // Leave password empty and submit
  const submitButton = await page.$('button[type="submit"]');
  if (submitButton) {
    await submitButton.click();
  }

  // Wait for error state to appear
  await page.waitForSelector('.error, [role="alert"], .text-red, .border-red', {
    timeout: 5000,
  }).catch(() => {
    // Error state may not appear, that's OK
  });

  // Wait a bit more for animations
  await new Promise((resolve) => setTimeout(resolve, 500));
};
