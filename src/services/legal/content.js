// Legal documents shown in the blocking consent gate. Bump LEGAL_VERSION when the text changes
// (users are then re-prompted to accept the new version). Kept in code so it versions with the app.

export const LEGAL_VERSION = '1.0';

export const LEGAL_SECTIONS = [
  {
    key: 'terms',
    title: 'Terms of Service',
    markdown: `**CypherMind AI** is an educational offensive-security platform for **students,
learners, and security professionals**. By using it you agree to the following.

- **Educational & authorized use only.** CypherMind is provided strictly for learning and for
  security testing that you are **explicitly authorized** to perform (your own systems, lab/CTF
  environments, or targets with written permission / an active engagement).
- **Account.** You are responsible for your account and for keeping access secure. One account
  is for one person.
- **Plans & payments.** Paid plans unlock higher limits/features. Payments are processed by our
  payment provider; plan validity is shown at purchase. Limits reset per your plan.
- **Acceptable use.** You will not use the platform to attack systems you are not authorized to
  test, to harm third parties, or to break any applicable law.
- **Availability.** The service is provided "as is" without warranty of uninterrupted operation.
- **Termination.** We may suspend accounts that violate these terms.`,
  },
  {
    key: 'privacy',
    title: 'Privacy Policy',
    markdown: `We collect the minimum needed to run the service.

- **What we store:** your email, basic profile (name, role, how you heard about us), your plan
  and transactions, and your chats/usage.
- **Chat history:** your conversations are retained for **30 days** and then automatically
  deleted. Long-term "memory" stores only salient snippets to improve your experience.
- **How we use it:** to operate the assistant, enforce plan limits, provide support, and send
  transactional emails (verification codes, receipts, expiry reminders).
- **Sharing:** we do not sell your data. We share only with essential providers (email, payments,
  hosting) to deliver the service.
- **Your control:** you may request deletion of your account and data at any time.`,
  },
  {
    key: 'responsibility',
    title: 'Security & Responsible-Use Consent',
    markdown: `This is the most important part. **Read it carefully.**

- **You are solely responsible for your actions.** CypherMind provides tools, commands, payloads,
  and techniques for **learning and authorized testing**. How you use them is **your
  responsibility alone**.
- **Authorization is yours to hold.** You confirm that for any target you test, you have the
  **legal right and explicit authorization** to do so. Using these capabilities against systems,
  accounts, or people **without authorization is illegal and strictly your own liability.**
- **No liability on the platform.** CypherMind, its authors, and operators are **not liable** for
  any misuse, damage, or unlawful activity performed by you. By accepting, you agree to **indemnify
  and hold harmless** the platform for anything you do with it.
- **You are of legal age** and use this platform for legitimate educational or authorized security
  work.

By ticking the box you acknowledge you have read and agree, and that **you accept full personal
and legal responsibility** for how you use CypherMind AI.`,
  },
];
