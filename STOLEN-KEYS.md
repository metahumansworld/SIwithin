# What a stolen key costs

Written 18 October 2026, the day after the OpenCode breach, as a plain account of where an API key can be taken from, what each layer of protection did in that case, and what SIwithin does and does not do about it. Sources at the end, with the day they were read.

## The case

On 17 October 2026 OpenCode, an open-source coding agent, said on X that it had a security breach the night before, tied to a large-scale distillation attack, affecting 1.4 percent of the users of OpenCode Console, the subset who had external providers linked. Its email to those users, as the coverage relays it, named unauthorized access to a legacy system being decommissioned and said third-party provider keys saved in the workspace may have been exposed. Users were told to revoke and replace the keys at each provider and to review recent usage. OpenCode said the incident was ongoing and that it was working with Anthropic, OpenAI and Google.

Console is OpenCode's optional hosted layer. By its own documentation, an administrator enters a provider's API key in a workspace, and Console stores it and serves the members' requests through its gateway, so the members never see the key. The keys that may have been exposed were those stored copies. Nothing published says the agent running on developers' machines was touched; a key entered locally lives in a file on the device.

Users reported spend alerts from the providers firing overnight, before OpenCode's notice; bills in the hundreds of dollars; in one case a cloud project suspended by its provider. How the attacker got in, how the keys were stored and what the keys were used for had not been published when this page was written.

## Three layers, and what each did

A stolen key is spent at the provider. Three things can notice or stop that:

1. **The provider's own limits and alerts.** In this case they were the detection: the alerts told the owners something was wrong hours before the vendor's email. They fired after the money was spent, and an alert revokes nothing. Anthropic's Console offers an organisation monthly spend limit and, per workspace, a limit and an email when spend reaches an amount you set; limits are per workspace, not per key, so one key per workspace is the way to bound one key.

2. **A budget in the tool that holds the key.** Console's documentation describes monthly caps enforced at its gateway. A thief holding the raw key calls the provider directly and never meets the gateway. A budget enforced at a door protects only what passes through the door, and nothing once a copy of the key exists outside it.

3. **A door instead of a key.** The program that runs on your behalf gets no key at all, only a way to make requests through a door you hold, which meters each one, stops at a budget and leaves a record. There is then no stored copy to steal from the tool, and nothing the program holds is worth anything outside the run.

SIwithin is the third layer, for one case: a coding agent run unattended on your own Mac.

## What SIwithin does

- The key stays with the runner, outside the fence, read by a command you name in the config. The run never holds it: the agent is given a token good for that one run, and a loopback address.
- Every request the run makes goes through the runner's proxy on that address. The proxy meters each one at the published prices, refuses with 402 once the run's budget is reached, and logs every request to the run's folder.
- A cap file bounds all runs together; a run that could pass the cap is refused before it starts.
- The run leaves a ledger line and a receipt, a hash chain over the run's files with the proxy's log among them, which `--verify` checks later.
- The fence refuses the run every socket but the proxy's loopback port (the network wall): no name lookup, no connection out. A second client inside the run reaches only the proxy, with the run's token, and is metered like the first.
- A process the run starts and leaves behind is found and killed when the run ends.

So the thing stolen at OpenCode, a raw provider key stored inside a tool, has no counterpart here; and a run that tries to spend beyond its budget, or to send anything anywhere but the API, is stopped and recorded.

## What SIwithin does not do

- It cannot protect a key you have given to someone else's server. A hosted service's copy of your key is only as safe as the service. The point of a door is that you need not give the key away.
- It fences a run, not your machine. Malware already on the computer, outside any run, is out of scope; so is a key kept in another tool's file.
- It does not watch your key's use outside its own runs. Spend on your provider bill that no receipt accounts for is the sign of a second user of the key; comparing the two is not yet built. Until it is, the provider's usage page, filtered to the key, is the place to look.
- macOS only, by `sandbox-exec`; it refuses to run elsewhere rather than run unfenced.

## What to do today, whichever tools you use

- Treat an AI key as a production credential, which is Anthropic's own advice in its September 2026 threat report. One key per tool, revoked when the tool goes.
- Set the provider's spend limit and the email notification, low. They are late, but they are what caught the OpenCode case.
- Read the usage page for each key for the days since 16 October 2026, and rotate any key that was ever entered into a hosted workspace.
- Prefer tools that take a door rather than a key.

## Sources, read 18 October 2026

- OpenCode's post on X, 17 October 2026: https://x.com/opencode/status/2111519637049319818
- OpenCode Console documentation (console, providers, budgets, workspaces): https://opencode.ai/v2/docs/console/
- Cyera, "OpenCode breach: what happened and how to rotate exposed AI API keys": https://www.cyera.com/research/opencode-breach-what-happened-and-how-to-rotate-exposed-ai-api-keys
- Noma Security, "OpenCode Console breach: what security teams need to know": https://noma.security/blog/opencode-console-breach-what-security-teams-need-to-know
- CellCog, with the notice's text and a timeline: https://cellcog.ai/blog/opencode-breach-api-keys/
- Anthropic, "Detecting and countering misuse of AI: September 2026": https://www.anthropic.com/threat-intelligence-report-september-2026
- Anthropic, "Strengthening our defenses against distillation attacks", 12 October 2026: https://www.anthropic.com/research/distillation-defenses
- Claude Console, workspaces and limits: https://support.claude.com/en/articles/9796807-creating-and-managing-workspaces-in-the-claude-console
- Claude Console, cost and usage reporting: https://support.claude.com/en/articles/9534590-cost-and-usage-reporting-in-the-claude-console
