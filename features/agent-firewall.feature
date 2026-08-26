Feature: The agent firewall says what it did, and can be told what to do

  The ask, verbatim, @yurii 2026-08-26: "роби по максимуму глибокий сервіс,
  тобто наш фільтр, щоб можна було його налаштовувати та мати повну
  статистику: на якому етапі, що було зроблено, що отримав агент, як діяв і
  так далі."

  What was there before. The firewall has been able to refuse a dangerous
  action since Ring 3.1 shipped, and it was correct. It was also mute. A
  refusal wrote one prose sentence, so a week of them could be read one at a
  time and never counted. Becoming untrusted, which is the thing that CAUSES
  every refusal, was written nowhere at all. And shadow mode, which docs/07
  B.9 names as the on-ramp every operator is supposed to start on, emitted
  no event whatsoever: it set a response header, so the only party told that
  a dangerous action had been permitted was the agent that had just been
  talked into it.

  Its policy was also a Rust literal. Adding one of your own tools to the
  source map meant a recompile and a redeploy, which is why in practice
  nobody ever adjusted it and every box ran the same nine starter tool names.

  Background:
    Given a gateway with the agent firewall switched on
    And the event stream is configured

  # @test:becoming_tainted_is_recorded_not_only_being_blocked
  Scenario: A run reads the web and the fact is written down
    Given an agent whose history shows it called a web search
    When it makes its next call
    Then the stream carries one event saying the run became untrusted
    And that event names the tool that carried the label in
    And it carries the run's full label set, so a later refusal needs no
      re-derivation

  # @test:a_shadow_would_block_is_recorded
  Scenario: Shadow mode permits a dangerous action and says so
    Given the firewall is in shadow
    And a run that has already touched the web
    When the model asks to run a shell
    Then the caller still gets its answer, because shadow does not block
    And the stream carries a would-block event at the medium band
    And an operator can therefore count a week of them before deciding

  # @test:the_record_says_which_rule_fired_at_which_stage_and_over_what
  Scenario: A refusal can be grouped, not only read
    Given the firewall is enforcing
    And a run that has already touched the web
    When the model asks to run a shell
    Then the call is refused
    And the record names the stage, the mode, the rule, the labels it was
      carrying, what was denied, and the tool it asked for by name

  # @test:a_policy_can_be_changed_without_a_rebuild
  Scenario: An operator writes their own policy
    Given a policy file naming their own tools, capabilities and one rule
    When the gateway loads it
    Then their rule is what decides, and no rebuild was needed

  # @test:one_tool_can_carry_more_than_one_label
  Scenario: One source carries more than one label
    Given a tool whose output is both an upload and personal data
    When the policy file gives it both labels
    Then a rule about either of them can fire

  # @test:anti_exfiltration_cannot_be_dropped_in_enforce_mode
  Scenario: The rule an operator cannot delete by accident
    Given a policy file that names only the operator's own rule
    When the gateway loads it in enforce mode
    Then anti-exfiltration is put back, first in the order
    And secrets plus an outbound capability is still refused

  # @test:shadow_mode_does_not_get_the_floor_forced_on_it
  Scenario: Shadow measures the operator's policy and not ours
    Given the same file loaded in shadow mode
    When the gateway loads it
    Then only the operator's own rule is present, so the week's numbers
      describe the policy they actually wrote

  # @test:a_config_that_cannot_be_read_stops_the_box_rather_than_falling_back
  Scenario: A broken policy file stops the gateway
    Given a policy file with a misspelled key or an unknown mode
    When the gateway starts
    Then it refuses to start rather than quietly running the built-in policy

  # @test:the_error_says_what_to_fix
  Scenario: The refusal names the field
    Given a policy file whose mode is not one of the three
    When the gateway refuses it
    Then the message names the field, the bad value, and the accepted ones

  # @test:an_empty_config_is_the_off_switch_not_the_starter_policy
  Scenario: An empty policy is empty
    Given a policy file that is an empty object
    When the gateway loads it
    Then nothing is classified and nothing is refused, rather than the
      built-in starter policy appearing in its place

  # @test:acquisitions_count_runs_not_events
  Scenario: The report counts runs, not chatter
    Given one run that read the web on several turns
    When the report is produced
    Then that label shows one run per run, so a chatty agent does not read
      as a fleet-wide problem

  # @test:the_enforce_projection_counts_only_what_shadow_let_through
  Scenario: The number the shadow week exists to produce
    Given a window containing both refusals and would-blocks
    When the report is produced
    Then it says how many actions turning enforcement on would refuse, over
      how many runs and agents, and which rule and agent carry most of it
    And it counts only what shadow let through, never what was already
      refused

  # @test:the_report_answers_all_four_questions
  Scenario: The report answers what was asked of it
    Given a window with an acquisition and a would-block
    When the report is produced
    Then it says how runs became untrusted, what the filter decided, what the
      agents tried to do, and at which stage

  # @test:an_empty_read_says_it_measured_nothing_rather_than_all_clear
  Scenario: Nothing measured is not the same as nothing found
    Given an event file with no firewall events in it
    When the report is produced
    Then it says it measured nothing and names the switch that would have
      produced some, rather than printing an all-clear

  # ---------------------------------------------------------------------
  # 2026-08-26, the second pass. @yurii, on reading what the first pass did
  # NOT do: "Це рівень 1 із docs/07 B.7, дорадчий: шлюз бачить tool_use у
  # відповіді моделі, а виконує інструмент клієнт. Той, хто ігнорує 403,
  # нічим із цього не спиняється. Рівні 2 і 3 не побудовані. Спадкування
  # taint у під-ранах не побудоване. Фаєрвол досі за замовчуванням off."
  # ---------------------------------------------------------------------

  # @test:a_sub_run_cannot_launder_its_parents_taint
  Scenario: A sub-agent cannot be used to wash the taint off
    Given a run that has read the web and is therefore untrusted
    And a child run whose own history is spotless
    When the child asks to run a shell
    Then it is refused, because it is judged against what its parent touched
    And the record says the labels came from a parent run, naming which

  # @test:a_run_that_declares_itself_its_own_ancestor_does_not_hang_the_box
  Scenario: A parent chain that loops does not take the gateway down
    Given two runs each declaring the other as its parent
    When either of them makes a call
    Then it is answered, rather than spinning inside a lock on the request path

  # @test:an_executor_can_ask_before_it_runs_the_tool
  Scenario: An executor asks permission before running a tool
    Given an executor that will act on the answer
    When it asks whether a tainted run may run a shell
    Then it is told no, before the tool has run rather than after

  # @test:the_two_doors_answer_the_same_way_about_one_run
  Scenario: Asking first and being judged after give the same answer
    Given one run and one tool
    When an executor asks, and the same run's model answer is judged
    Then both say the same thing, naming the same rule

  # @test:a_firewall_that_is_off_says_allow_and_ungoverned_not_just_allow
  Scenario: Permitted and unjudged are not the same answer
    Given a gateway whose firewall is off
    When an executor asks whether it may run a tool
    Then it is told the call is allowed and that nothing judged it, so it
      cannot record a governance gap as a permission

  # @test:the_mcp_door_refuses_a_tool_a_tainted_run_may_not_use
  Scenario: The MCP door stops it whether or not anybody asked
    Given a broker pointed at a gateway that judges
    When a tainted run calls a tool through it
    Then the call is refused before any secret is injected and before the
      upstream is reached

  # @test:an_allowed_tool_still_reaches_the_upstream
  Scenario: The MCP door lets ordinary work through
    Given the same broker and a call nothing objects to
    When it is made
    Then it reaches the upstream unchanged

  # @test:a_call_with_no_run_id_is_refused_only_when_the_gate_is_fail_closed
  Scenario: A call with no run cannot be judged, and that is the operator's call
    Given an MCP call carrying no run identity
    When the gate is fail-open, then fail-closed
    Then it is let through in the first case and refused in the second, and
      the refusal names the header that would fix it

  # @test:a_gateway_that_cannot_be_reached_does_not_silently_become_permission
  Scenario: A judge that cannot be reached is recorded, not assumed
    Given a broker whose gateway is down
    When a tool call arrives
    Then fail-open lets it through and records that nothing governed it

  # @test:the_default_is_shadow_so_a_box_that_asked_for_nothing_still_measures
  Scenario: A box that configured nothing still measures
    Given a gateway started with no firewall setting at all
    When it runs
    Then the firewall is in shadow, refusing nothing and recording everything
    And setting it to off still turns it off

  # @test:the_record_says_which_instruction_the_turn_carried
  Scenario: Which instruction the turn carried
    Given a run that became untrusted and then tried something dangerous
    When both events are written
    Then each carries the same hash of the instruction that turn was given
    And no word of the instruction appears anywhere on the bus

  # @test:a_turn_with_no_instruction_records_no_hash_rather_than_an_empty_one
  Scenario: A turn with no instruction says so
    Given an agent-driven turn carrying only tool results
    When it is recorded
    Then the instruction field is absent rather than empty, because "we looked
      and there was nothing" is a different claim from "this turn had none"

  # @test:the_same_instruction_hashes_to_the_same_value_across_turns
  Scenario: Four incidents from one instruction are recognisable as one
    Given the same instruction given on turn one and again on turn five
    When both are hashed
    Then they are the same value, so incidents group by what caused them

  # @test:it_is_a_hash_and_carries_no_word_of_the_prompt
  Scenario: The instruction is stored by hash and only by hash
    Given an instruction containing a passphrase and a card number
    When it is hashed
    Then the result carries neither, and there is nothing here to erase

  # @test:an_inherited_label_is_not_reported_as_a_tool_this_run_called
  Scenario: The report does not send you looking for a tool that is a run
    Given one run that read the web and one that inherited it
    When the report is produced
    Then the tool is credited once and the inheritance is counted separately

  # ---------------------------------------------------------------------
  # 2026-08-26, the detector. @yurii: "берись за детектор" — as a taint
  # SOURCE and never as a decision, so the attacker's own text has no vote
  # in the verdict it produces.
  # ---------------------------------------------------------------------

  # @test:an_injection_in_a_trusted_source_is_still_an_injection
  Scenario: A source the operator trusts, carrying something the world put in it
    Given a policy in which the internal ticket system is a trusted source
    And a ticket containing an instruction to ignore previous instructions
    When the model then asks to run a shell
    Then the call is refused, because a trusted pipe is not trusted water
    And the record names the tool whose OUTPUT carried it, and the pattern
      that matched, and no word of the ticket

  # @test:an_ordinary_tool_result_raises_nothing
  Scenario: An ordinary ticket is left alone
    Given a ticket that happens to say "please ignore the duplicate reports"
    When the agent reads it
    Then nothing is raised, because a person being polite about duplicates is
      not an override

  # @test:ordinary_documents_stay_quiet
  Scenario: Ten ordinary documents, each containing a word a naive pattern
      would fire on
    When each is scanned
    Then none of them raises a signal, because a detector that fires on
      ordinary text gets switched off and takes the coarse model with it

  # @test:the_shapes_an_injection_takes_are_recognised
  Scenario: The shapes an injection takes
    Given text that overrides instructions, impersonates the system, asks for
      the context to be sent somewhere, solicits a secret, directs a tool, or
      hides itself
    When it is scanned
    Then each shape is recognised by name

  # @test:a_signal_is_a_name_and_never_the_text_it_matched
  Scenario: A signal is a name and never the text
    Given a document containing both an override and a passphrase
    When it is scanned
    Then what comes back names the pattern and carries neither

  # @test:the_users_own_words_are_not_scanned
  Scenario: The operator's own words are not scanned, and that is a decision
    Given a user message that itself says to ignore all previous instructions
    When the request is scanned
    Then nothing is raised, because that is a person typing and a security
      engineer must be able to do their job

  # @test:a_result_whose_call_scrolled_out_of_the_window_is_still_scanned
  Scenario: Trimming the history is not a way past the scan
    Given a tool result whose call has scrolled out of the request
    When it is scanned
    Then it is still scanned, attributed to no tool rather than dropped

  # @test:a_tool_result_is_attributed_to_the_tool_that_produced_it
  Scenario: The record names the tool to stop calling
    Given two tools whose results both arrive in one message
    When they are read
    Then each is attributed to the call that produced it

  # @test:a_policy_written_before_the_detector_existed_still_acts_on_its_label
  Scenario: Silence about a label that did not exist is not consent
    Given a policy written before the detector existed
    When it is loaded in enforce mode
    Then the detector's label is denied by a rule that was added, because
      otherwise the case the detector exists for is the case they miss

  # @test:an_operators_own_rule_about_the_label_wins_over_the_floor
  Scenario: An operator who says something about the label is not silent
    Given a policy with its own, narrower rule about the label
    When it is loaded
    Then nothing is added behind their back and their rule is what decides

  # @test:the_detector_has_an_off_switch_that_is_really_off
  Scenario: The detector has an exit
    Given a policy that sets detect_injection to false
    When it is loaded
    Then there is no scan, no label and no rule, because a floor with no exit
      is one somebody escapes by turning the whole firewall off

  # @test:one_document_reports_each_kind_once_however_many_times_it_tries
  Scenario: Forty attempts of one kind are one finding
    Given a document that overrides instructions three different ways
    When it is scanned
    Then it reports one kind, so a count measures kinds and not persistence

  # ---------------------------------------------------------------------
  # 2026-08-26. What the document SAID. The record could name the shape
  # that matched, the tool whose output carried it, and the run's whole
  # label set, and it could not say one thing: what the stranger's document
  # actually said. That sentence is the reason somebody opens the event.
  # ---------------------------------------------------------------------

  # @test:the_excerpt_carries_the_sentence_and_not_only_the_match
  Scenario: The record says what the document said
    Given a ticket from a source the operator marked trusted
    And the ticket carries an instruction to ignore previous instructions
    When the excerpt is taken
    Then it carries the sentence around the match and not only the match,
      because twenty characters of an override explains nothing an operator
      can act on

  # @test:a_quote_that_is_whole_is_not_marked_clipped
  Scenario: A whole quote is not marked as cut
    Given a short document whose every word fits
    When the excerpt is taken
    Then nothing says it was cut, because a reader who cannot tell a whole
      quote from a cut one draws a conclusion from a sentence that ended
      mid-clause

  # @test:a_quote_that_was_cut_says_so_at_the_edge_that_was_cut
  Scenario: A cut quote says so, at the edge that was cut
    Given a long document with the override buried in the middle of it
    When the excerpt is taken
    Then it is marked as cut and shows an ellipsis at each end that was cut

  # @test:a_secret_in_the_document_is_redacted_by_the_redactor_this_crate_already_has
  Scenario: A credential in the attacker's document does not reach the record
    Given an injected document that quotes an AWS access key
    When the excerpt is taken
    Then the key is replaced by the DLP scanner this crate already has, and
      no second redactor is written

  # @test:a_secret_lying_across_the_edge_of_the_window_is_never_recorded_in_halves
  Scenario: A credential lying across the edge is not recorded in halves
    Given a key positioned so the excerpt's own edge falls inside it
    When the excerpt is taken, at every offset in a swept range
    Then no fragment of the key survives, because half a key no longer
      matches the pattern that would have removed it and nothing would report
      that it got out

  # @test:the_address_the_attacker_wants_the_data_sent_to_survives_the_default_pass
  Scenario: The destination survives the pass that runs by default
    Given an injected document telling the agent to email a customer list to
      an outside address
    When the excerpt is taken with the default redaction
    Then the address is still readable, because it is what an operator blocks
      and greps their egress logs for
    But when the PII pass is chosen instead, the address is removed and that
      cost is the operator's to accept

  # @test:the_default_pass_is_the_one_that_keeps_a_credential_out_of_the_record
  Scenario: The default is the pass that keeps a credential out of a log
    When a caller does not choose a redaction
    Then secrets are removed and people are not

  # @test:two_kinds_in_one_sentence_are_one_excerpt_naming_both
  Scenario: One sentence that does two things is quoted once
    Given a sentence that both overrides instructions and asks for the
      context to be posted somewhere
    When the excerpts are taken
    Then there is one of them and it names both kinds, rather than the same
      two hundred characters appearing in the record twice

  # @test:two_kinds_in_different_places_are_two_excerpts
  Scenario: Two places in one document are two quotes
    Given a document that tries something at the top and something else six
      hundred characters later
    When the excerpts are taken
    Then there are two, so folding everything into one entry would lose the
      second place it tried

  # @test:forty_attempts_of_one_kind_do_not_become_forty_excerpts
  Scenario: Forty attempts of one kind are still one quote
    Given a document that repeats one override forty times
    When the excerpts are taken
    Then there is one, matching how the signals themselves count kinds rather
      than persistence

  # @test:the_length_of_the_record_is_not_the_attackers_to_choose
  Scenario: The attacker does not choose how long the record is
    Given a four hundred kilobyte document full of every shape at once
    When the excerpts are taken
    Then at most six of them are kept and each is capped, because a line whose
      length an attacker picks is a way to fill an operator's disk with their
      prose

  # @test:control_characters_never_reach_the_record
  Scenario: Nothing in the quote is obeyed rather than printed
    Given a document carrying an escape sequence, a newline and a
      right-to-left override
    When the excerpt is taken
    Then no control character survives, because a consumer that parses the
      line and prints the value hands whatever is in it straight to a terminal

  # @test:the_invisible_character_that_caused_the_signal_is_made_visible
  Scenario: The character nobody can see is shown
    Given a document whose only fault is a zero-width space
    When the excerpt is taken
    Then the character is written out as its code point, because an excerpt
      that looks like an ordinary sentence reads as a false positive

  # @test:the_detector_and_the_sanitiser_read_one_list_of_invisible_characters
  Scenario: One list of invisible characters, not two that agree today
    Given every boundary of the hidden-text ranges
    When each is scanned and then excerpted
    Then the detector fires and the character is made visible, because the
      pattern and the sanitiser are built from the same array

  # @test:the_excerpts_and_the_scan_never_disagree_about_which_kinds_fired
  Scenario: The quotes and the signals never disagree
    Given a document that fires all six kinds
    When it is both scanned and excerpted
    Then the two answers name the same kinds, so an operator reading either
      member comes away with the same list

  # @test:an_excerpt_is_a_member_of_its_own_and_signals_stay_names
  Scenario: Signals stay names and the words go somewhere else
    Given an excerpt attached to a taint-raised record
    When the record is read
    Then the signals member still carries names alone and the words arrive in
      a member of their own, so a consumer that wants no content drops one key

  # @test:a_record_with_nothing_to_quote_is_the_record_it_was_before
  Scenario: A deployment that stores nothing looks exactly as it did
    Given a deployment that has not turned excerpt storage on
    When a taint-raised record is built
    Then it is byte for byte the record it was before this existed, with no
      empty array announcing a feature nobody asked for

  # @test:whatever_the_document_did_the_event_is_still_one_line
  Scenario: One event is still one line of NDJSON
    Given a document containing newlines, quotes and backslashes
    When the event is written through the real exporter
    Then the file holds exactly one line and it parses

  # ---------------------------------------------------------------------
  # 2026-08-26, B.4. The release valve, and the honest answer about the
  # other two gates.
  # ---------------------------------------------------------------------

  # @test:a_human_who_reviewed_the_context_can_let_a_label_go
  Scenario: A human reviewed the page and says so
    Given a run refused because it read the web
    When a person who reviewed the page clears that label, with a reason
    Then the run is allowed again
    And the clearance is recorded at the same band a refusal takes

  # @test:a_clearance_is_spent_by_the_next_arrival_of_that_label
  Scenario: A review covers what was there, not what comes next
    Given a run whose label a human has cleared
    When it reads the web again
    Then it is refused again, because a fresh page is a fresh page

  # @test:clearing_a_child_says_the_parent_still_carries_it
  Scenario: Half a job says which half
    Given a child run whose parent is still untrusted
    When somebody clears the child
    Then the answer names what is still arriving from the parent, so the valve
      does not read as broken when the label returns

  # @test:secrets_cannot_be_let_go_at_all
  Scenario: One label no review can remove
    Given a run that has read a secret
    When somebody tries to clear that label
    Then it is refused by name, because clearing it would disable
      anti-exfiltration by another door

  # @test:a_clearance_with_no_human_and_no_reason_is_not_a_clearance
  Scenario: An agent may not clear its own taint
    Given a clearance whose actor is an agent, or which carries no reason
    When it is submitted
    Then nothing is cleared and the answer says why

  # @test:taint_flows_down_a_chain_and_never_up_it
  Scenario: A quarantine contains rather than spreads
    Given a sub-run that reads a dirty document on its caller's behalf
    When the caller makes its next call
    Then the caller is still clean, and the quarantine is still refused

  # ---------------------------------------------------------------------
  # 2026-08-26, block A2. Verifying a delegation is a library call.
  # ---------------------------------------------------------------------

  # @test:a_delegation_verifies_and_the_chain_keeps_its_root
  Scenario: An enforcement point checks a delegation with what it already holds
    Given a key set held locally and a token from vouchryx
    When it is verified
    Then the chain comes back with the person at its root, because the RFC
      keeps the subject out of the actor claim and this estate puts it in

  # @test:a_token_presented_by_the_wrong_holder_is_refused
  Scenario: A stolen delegation token is bytes
    Given a token bound to one key and a proof from another
    When it is verified
    Then it is refused, which is the whole reason the binding exists

  # @test:a_bound_token_checked_with_no_proof_is_refused_rather_than_downgraded
  Scenario: Forgetting to check the binding is not the same as it passing
    Given a sender-constrained token and a caller that passed no proof
    When it is verified
    Then it is refused rather than accepted with the binding skipped

  # @test:a_revoked_delegation_is_refused_though_its_signature_is_perfect
  Scenario: The signature is fine and the authority is gone
    Given a token whose delegation has been revoked
    When it is verified
    Then it is refused, because that is what a revocation list is for

  # @test:the_algorithm_still_comes_from_the_key_on_this_path
  Scenario: One copy of the algorithm rule, not two that agree today
    Given a second verifier in the same process
    When it decides which algorithms a key may be used with
    Then it asks the same function the first one does

  # ---------------------------------------------------------------------
  # 2026-08-26, block B1 and B2. The compliance catalog gains DORA and
  # NIS2, and three OWASP rows that were missing. Two of the three.
  # ---------------------------------------------------------------------

  # @test:every_declared_framework_is_actually_cited_by_a_control
  Scenario: A framework nobody cites is a promise nobody kept
    Given a framework declared in the catalog's registry
    When the catalog is read
    Then some control cites it, because a customer reading the framework list
      and asking which controls cover it must not get none

  # @test:dora_and_nis2_are_cited_by_article_and_never_by_sub_point
  Scenario: Cited at the level the identifier can be defended at
    Given a DORA or NIS2 row
    When it is read
    Then it names an article and its subject and never a sub-point letter,
      because a wrong letter is a mis-citation and a right article is not

  # @test:the_owasp_rows_added_in_this_pass_are_the_ones_that_were_asked_for
  Scenario: Two of the three, and the third said plainly
    Given the OWASP categories this catalog claims
    When they are read
    Then unexpected code execution and human-agent trust exploitation are
      among them, and insecure inter-agent communication is not, because the
      agents here do not talk to each other across a trust boundary
