# Kali Submission Status Notifications

The scheduled `Kali submission status` workflow checks the public Kali issue
every six hours. When status or resolution changes, it:

1. Updates the local GitHub submission tracker issue.
2. Applies a persistent `kali-status-*` label.
3. Sends an email when SMTP repository secrets are configured.

## Activation

After submitting the New Tool Request, set its numeric Kali issue ID:

```bash
gh variable set KALI_BUG_ID --body "12345"
```

Configure email secrets. For Gmail, use an app password rather than the account
password:

```bash
gh secret set SMTP_HOST --body "smtp.gmail.com"
gh secret set SMTP_PORT --body "465"
gh secret set SMTP_USER --body "1200km@gmail.com"
gh secret set SMTP_PASSWORD
gh secret set SMTP_FROM --body "1200km@gmail.com"
gh secret set NOTIFY_EMAIL --body "1200km@gmail.com"
```

Run the workflow manually once after configuration:

```bash
gh workflow run kali-status.yml
```

The workflow never stores SMTP credentials in the repository. If email secrets
are absent, issue status tracking continues and email delivery is skipped.
