# Phishing Case Studies

## Overview

This document presents three phishing investigations from a collection of 22 real emails I found in my own Gmail and Yahoo junk folders. I used my custom analyzer (`analyzer/enrich_phish.py`) to help with the initial triage, then reviewed the relevant messages and attachments using `analyzer/inspect_attachments.py`.

> **Scope and ethics:** I received all samples unsolicited in mailboxes that I own. I analyzed them statically: I did not visit any links or execute any attachments. All indicators are defanged. For more information, see [`docs/ethics-and-scope.md`](ethics-and-scope.md).

The initial triage classified 3 of the 22 samples as **LIKELY MALICIOUS**, 8 as **SUSPICIOUS**, and 11 as **LIKELY BULK/BENIGN** (authenticated marketing emails). I selected the three cases below because they show different ways phishing can work: one message failed email authentication, another passed authentication despite impersonating an authority figure, and the third relied on an image and a phone call rather than a detectable link or executable file.

---

## Case 1 — CEO impersonation / Business Email Compromise (authentication failed)

| Field | Value |
|---|---|
| Sample | `phish-yahoo-08.eml` |
| From | `MR JOHN <12300@wtp[.]ac[.]th>` |
| Reply-To | `bankofamericamrbriantmoynihant@gmail[.]com` |
| Subject | *(blank)* |
| Source IP | `209[.]85[.]167[.]178` (Google LLC) |
| Auth | **SPF softfail · DKIM pass · DMARC fail** |
| Verdict | **Malicious** — advance-fee / Business Email Compromise |
| MITRE ATT&CK | T1566 Phishing · T1598 Phishing for Information · T1656 Impersonation |

### Analysis

The message attempts to impersonate Brian Moynihan, the CEO of Bank of America. The sender details immediately raised concerns. The visible sender is a numeric mailbox on a Thai academic domain (`wtp.ac.th`), while the Reply-To address uses a Gmail account containing the CEO's name.

The sending IP belongs to Google. SPF returned a softfail because Google was not an authorized sender for the `wtp.ac.th` domain. DKIM passed, but DMARC failed. In this case, the authentication results did not support the message's apparent sender identity.

The most important indicator I identified was the **mismatch between the From and Reply-To addresses**. Although the email appears to come from one account, replies would go to a different Gmail address. This is important because the scam depends on getting the recipient to respond. Once the recipient replies, the sender can continue the conversation and attempt to persuade them to make a fraudulent payment or transfer.

### Response actions

I would block or junk both the sender and Reply-To addresses, add them to the mail gateway's denylist, and alert the affected user. I would also search for other messages containing the same Reply-To address to check whether the same address was used in other attempts.

### IOCs

`12300@wtp[.]ac[.]th` · `bankofamericamrbriantmoynihant@gmail[.]com` · `209[.]85[.]167[.]178`

---

## Case 2 — Authority impersonation (authentication passed)

| Field | Value |
|---|---|
| Sample | `phish-yahoo-01.eml` |
| From | `FBI DIRECTOR <filloffice018@gmail[.]com>` |
| Reply-To | `fbidirectorkashpatel1503@gmail[.]com` |
| Subject | `Notification Regarding Funds Available for Collection` |
| Source IP | `209[.]85[.]167[.]177` (Google LLC) |
| Auth | **SPF pass · DKIM pass · DMARC pass** |
| Verdict | **Malicious** — advance-fee / authority impersonation |
| MITRE ATT&CK | T1566 Phishing · T1598 Phishing for Information · T1656 Impersonation |

### Analysis

This case stood out during my investigation because the email claims to be from the FBI Director, but all three email authentication checks passed: SPF, DKIM and DMARC.

The reason is that the message was sent from a genuine Gmail account. The sender used **"FBI DIRECTOR" as the display name**, but the actual email address belongs to Gmail. The authentication results confirm that the message was sent through an authorized Gmail account. They do not confirm that the person behind the account is an FBI official.

Comparing this case with Case 1 helped me understand an important limitation of email authentication. In Case 1, the authentication results exposed a problem with the claimed sending domain. In this case, the results passed because the sender used a real Gmail account. However, the display name and the content of the message were still deceptive.

A passing SPF, DKIM and DMARC result should therefore not be treated as proof that an email is legitimate. It only provides information about the sending domain and authentication. The analyst still needs to examine the display name, Reply-To address, sender address and reason for the message.

### Response actions

I would report the Gmail accounts to the provider and add the addresses to the organization's denylist. I would also share an awareness notice with users explaining that an email claiming to be from a government authority should not be trusted based on its display name alone. The message's request to collect funds by email is another reason to treat it as suspicious.

### IOCs

`filloffice018@gmail[.]com` · `fbidirectorkashpatel1503@gmail[.]com` · `209[.]85[.]167[.]177`

---

## Case 3 — Callback phishing / TOAD (no detectable payload)

| Field | Value |
|---|---|
| Samples | `DuBuque, Schmitt and Rodriguez.eml`, `Effertz Group.eml` |
| From | Gibberish Gmail accounts (`rfctewfepcrlexv@gmail[.]com`, `wtalucumvnaqlwup@gmail[.]com`) |
| Attachment | 2 MB BMP image, 763×902 px (one per email) |
| Auth | SPF pass · DKIM pass · DMARC pass (sent from real Gmail) |
| Verdict | **Malicious** — callback phishing (Telephone-Oriented Attack Delivery) |
| MITRE ATT&CK | T1566.001 Spearphishing Attachment · T1656 Impersonation |

### Analysis

The two emails use the same general approach. Each message contains a BMP image rather than a normal text-based email body. The image imitates a PayPal receipt and claims that the recipient has been charged **USD $672.67 or $423.14** for a *"Springfield Armory Gun."* It then tells the recipient to call a customer support number within 24 hours to cancel the transaction.

The two messages follow the same template, but use different amounts, invoice IDs and fabricated billing-company names. This suggests that the messages are part of an automated campaign.

I examined the attachments as part of the lab analysis. The results showed why this type of phishing can be difficult for conventional email security tools to detect:

| Evasion technique | Effect | Evidence from this lab |
|---|---|---|
| **Image-only body** | Makes keyword and text-based filtering less effective | `strings` extraction returned no lure text because the message content is rendered as pixels |
| **No links or executable file** | Leaves URL scanners and sandboxes with nothing to visit or execute | The attachment was confirmed as a genuine BMP, with no overlay or embedded code |
| **Phone-number obfuscation** | Can interfere with regular-expression-based extraction | The number was written as `+1[840]-{230}-[2274}` with decoy brackets |
| **Panic-based pretext** | Pressures the recipient to act quickly | The message claims that a $672 firearm purchase was made and refers to a 24-hour deadline |

In this case, there was no URL or malware sample for the usual automated checks to analyze. VirusTotal had no record of the files, and automated IOC extraction did not identify the main lure. The information became visible when I safely rendered and inspected the BMP image.

The actual attack path is the phone call. A recipient who calls the number may be connected to a fake support agent. The agent can then try to convince the victim to install remote-access software or buy gift cards. This means that an email can still lead to fraud even when it contains no malicious link or executable attachment.

### Deobfuscated IOC — callback number

`+1 840-230-2274` (the same number appears in both emails).

### Response actions

I would move the messages to junk, denylist the sender accounts and block the attachment hashes. I would also warn users not to call phone numbers included in unexpected payment or purchase receipts. Instead, they should check their account through the company's official website or contact the company using a verified number. Since the emails impersonate PayPal, I would also report the callback number to PayPal.

### IOCs

Callback number: `+1 840-230-2274`

Sender accounts: `rfctewfepcrlexv@gmail[.]com` · `wtalucumvnaqlwup@gmail[.]com`

BMP SHA-256:

- `cebf5b4b39b614ec957f072affa1e73940324ae7605efdad7c4034694ae7718c`
- `8a6edb022020b2a60a621e569e722df6282e90edf19b7cf87c937c2aef6fb58b`

---

## Lessons from the three cases

These investigations showed me that phishing analysis cannot rely on one security tool or one technical result. Each case required looking at the message in context and comparing the available indicators.

1. **Email authentication is useful, but it is not a final verdict.** Case 1 failed authentication checks, while Case 2 passed them. Both messages attempted to impersonate authority figures. The difference was that the second sender used a genuine Gmail account and a deceptive display name.

2. **A clean reputation result does not automatically mean a file or sender is safe.** New domains and previously unseen attachments may not have an established reputation. In other words, an unknown indicator should not automatically be treated as safe.

3. **Not every phishing email contains a link or malware.** Case 3 used an image and a phone number to direct the recipient into the next stage of the scam. This type of message can be missed by tools that focus mainly on URLs, text and executable files.

4. **Context is an important part of the analyst's work.** The display name, Reply-To address, message pretext, sender reputation and sending infrastructure all contributed to the analysis. The results from automated tools were useful, but reviewing the actual email and attachment was necessary to understand how each attempt worked.
