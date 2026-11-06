#!/usr/bin/env python3
"""Throwaway: plant one named mutant by an exact-string edit. Each must match exactly once."""
import sys
P='crates/gateway/src/provider.rs'; T='crates/gateway/src/settle.rs'; X='crates/gateway/src/proxy.rs'; E='crates/gateway/src/estimate.rs'
OUT='''            complete: whole_document
                || report == UsageReport::Final
                || (closed && report == UsageReport::Running),'''
M={
'complete-always-true':(P,'            complete: whole_document\n','            complete: true || whole_document\n'),
'complete-always-false':(P,OUT,'            complete: false && (whole_document || report == UsageReport::Final || (closed && report == UsageReport::Running)),'),
'whole-document-not-complete':(P,'            whole_document = true;','            whole_document = false;'),
'close-does-not-promote-running':(P,'|| (closed && report == UsageReport::Running),','|| (closed && report == UsageReport::Running && false),'),
'close-alone-is-complete':(P,'|| (closed && report == UsageReport::Running),','|| closed,'),
'done-is-not-a-close':(P,'                    closed = true;\n                    continue;','                    closed |= false;\n                    continue;'),
'message-stop-is-not-a-close':(P,'== Some("message_stop");','== Some("never");'),
'nothing-says-still-open':(P,'    delta_is_open || a_choice_is_open\n','    (delta_is_open || a_choice_is_open) && false\n'),
'open-delta-not-read':(P,'    delta_is_open || a_choice_is_open\n','    (delta_is_open && false) || a_choice_is_open\n'),
'open-choice-not-read':(P,'    delta_is_open || a_choice_is_open\n','    delta_is_open || (a_choice_is_open && false)\n'),
'open-choice-all-not-any':(P,'.any(|c| c.get("finish_reason")','.all(|c| c.get("finish_reason")'),
'message-start-reports-final':(P,'''    if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
        apply_anthropic(usage, u);
    }
''','''    if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
        apply_anthropic(usage, u);
        if u.get("output_tokens").is_some() {
            return UsageReport::Final;
        }
    }
'''),
'total-is-not-a-figure':(P,'&["completion_tokens", "total_tokens"]','&["completion_tokens"]'),
'any-key-is-a-figure':(P,'.any(|k| u.get(*k).is_some_and(|n| n.is_u64()));','.any(|k| u.get(*k).is_some());'),
'last-event-decides':(P,'report = report.max(merge_usage(&mut usage, &mut netting, &v));','report = merge_usage(&mut usage, &mut netting, &v);'),
'complete-not-asked':(T,'if !complete && unmeasured_output > 0 && usage.carries_priced_tokens() {','if (!complete || true) && unmeasured_output > 0 && usage.carries_priced_tokens() {'),
'zero-cap-not-asked':(T,'if !complete && unmeasured_output > 0 && usage.carries_priced_tokens() {','if !complete && usage.carries_priced_tokens() {'),
'priced-not-asked':(T,'if !complete && unmeasured_output > 0 && usage.carries_priced_tokens() {','if !complete && unmeasured_output > 0 {'),
'cap-replaces-a-higher-report':(T,'output_tokens: usage.output_tokens.max(unmeasured_output),','output_tokens: unmeasured_output,'),
'no-cap-on-the-output':(T,'output_tokens: usage.output_tokens.max(unmeasured_output),','output_tokens: usage.output_tokens,'),
'the-whole-estimate':(T,'return (cost, record, CostBasis::PartialUsage);','let _ = cost;\n            return (unmeasured, record, CostBasis::PartialUsage);'),
'record-keeps-the-counts':(T,'return (cost, record, CostBasis::PartialUsage);','let _ = record;\n            return (cost, usage, CostBasis::PartialUsage);'),
'record-loses-the-observation':(T,'''                tool_calls: usage.tool_calls,
                ..Usage::default()''','''                tool_calls: None,
                ..Usage::default()'''),
'refusal-gets-the-cap':(T,'(Microusd::ZERO, 0)','(Microusd::ZERO, self.output_cap_tokens)'),
'break-publishes-nothing':(P,'''                let chunk = chunk.map_err(|e| {
                    *usage_writer.lock().unwrap() = Some(parser.finish());
                    ProviderError::Upstream(e.to_string())
                })?;''','''                let chunk = chunk.map_err(|e| {
                    ProviderError::Upstream(e.to_string())
                })?;'''),
'cap-ignores-completions':(X,'crate::estimate::output_cap_tokens(parsed.max_tokens, parsed.completions),','crate::estimate::output_cap_tokens(parsed.max_tokens, 1),'),
'cap-ignores-max-tokens':(X,'crate::estimate::output_cap_tokens(parsed.max_tokens, parsed.completions),','crate::estimate::output_cap_tokens(None, parsed.completions),'),
'zero-completions-is-free':(E,'.saturating_mul(completions.max(1))','.saturating_mul(completions)'),
'partial-settlement-is-silent':(T,'''            tracing::warn!(
                model = %self.attribution.model,
                output_cap_tokens = self.output_cap_tokens,''','''            tracing::debug!(
                model = %self.attribution.model,
                output_cap_tokens = self.output_cap_tokens,'''),
'stub-declared-usage-incomplete':(P,'                (usage, true)\n','                (usage, false)\n'),
'stub-parsed-usage-always-complete':(P,'                (parsed.usage, parsed.complete)\n','                (parsed.usage, true)\n'),
}
if __name__=='__main__':
    if sys.argv[1]=='--list':
        import json; print(json.dumps(list(M))); sys.exit()
    if sys.argv[1]=='--check':
        bad=0
        for k,(f,a,b) in M.items():
            n=open(f).read().count(a)
            if n!=1: print('BAD',k,n); bad+=1
        print(len(M),'mutants,',bad,'bad'); sys.exit(bad)
    f,a,b=M[sys.argv[1]]
    s=open(f).read()
    assert s.count(a)==1,(sys.argv[1],s.count(a))
    open(f,'w').write(s.replace(a,b))
    print('planted',sys.argv[1],'in',f)
