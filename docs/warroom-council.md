# War room case discussion

The native entry points are `/api/warroom/conversations` and the existing
fleet/server/case UI. A website or analytics collector is never required.
The activity map is on the left; the shared case chat is on the right. The
normal composer and turn components are shared with individual case chats.

## Scope and participants

An administrator selects the lead Investigator and up to four role/server pairs:
Responder, Reviewer, Learner and Operator. A server can contribute multiple roles.
Each gets a fresh, read-only delegate of its existing configured role, using that
role's model/instructions and cost ledger. Original response/learning/review
procedures and live session ownership are unchanged. All delegates have exactly
one tool, the scoped evidence broker; no response, resolution, shell, arbitrary
file/SQL, secret or configuration tools are granted.

The grant contains only selected enrolled servers and the linked case's server.
A source turn reads only its own server; lead turns can connect the selected
sources. The linked case is validated against existing server records, never a
user-supplied title or external URL. Enrollment hashes are stored privately, so
replacement/re-enrolled machines cannot inherit previous discussion access.

The Investigator frames the case, source roles answer in order and the
Investigator closes. Each source returns JSON with `kind` (`evidence`, `answer`,
`correction`, `pass`), `note`, `evidence` references and `addresses` entry IDs.
Accepted citations must have been returned by that job's broker: `event:<sequence>`
or `record:<server>:<kind>:<id>`. A ledger retains at most 256 references per grant,
outside the analytics database. A contribution has at most eight citations,
four addressed entries and 2,000 bytes of text.

Unread references, exact text repeats, reused evidence-only contributions and
already-addressed evidence/question combinations are suppressed. Answers and
corrections must identify a preceding entry. A pass/invalid result becomes a
small system status, not an invented answer. These checks prove provenance and
bounded deduplication, not logical entailment or every semantic paraphrase.
Peer assertions and source summaries remain untrusted; repeated model analysis
is not independent corroboration. Conclusions must preserve contradictions,
unknown vectors and missing evidence; no vote establishes truth or authorizes a
response. The admin decides under KodeBlue's existing response policy.

## Lifecycle and efficiency

Native messages and turn reservations commit atomically. Only one turn per
conversation is dispatched at a time; concurrent ticks/restarts cannot dispatch
it twice. Workers retain native semaphore, model-budget, replay, Stop, transcript
and accounting behavior. The hub coordinator makes no separate model calls.

Messages arriving mid-turn are stored for the next speaker. During the closing
turn they request another bounded round. Pause stops future admission. End
withdraws queued work; dispatched work can finish and its completion cannot
reopen the case. Use the native worker-session Stop to abort current work. Failed
source turns remain explicit gaps. Changed enrollments/scope pause admission.
Models cannot select participants, create a discussion, call each other or write
response policy.

There are at most 32 retained conversations, 32 entries/96 KiB per conversation,
three rounds and four specialist turns/round, with a two-hour admission lifetime.
There is one active discussion per linked case or selected-server grouping.
Entries fit 2,400 encoded bytes; model excerpts link to full native cases and
oversized admin input is rejected. Jobs retain 24 reads/32 KiB per response,
ten-minute runs and thirty-minute grants. Context carries the latest twelve
entries/700 bytes each and the latest question. Evidence is a bounded received
view, not an exhaustive or transactionally consistent live snapshot. Inventory
can be stale, and native record payloads minimize fields and flag truncation.

Only a closing turn sends a normal notification; interim turns/passes remain in
chat and native case history. Conversations expire after thirty days on new
admission. Existing optional traffic APIs/policies remain compatible; traffic
collection and automatic traffic jobs do not automatically convene a council.

The implementation can investigate normal KodeBlue cases with the analytics
module disabled. Optional traffic snapshots are restricted to linked configured
collectors, granted sources, a fixed sequence ceiling and a maximum of eight
collectors/job. Source turns exclude browser claims. No external enrichment is
triggered by a discussion. IP enrichment retains its independent opt-in policy.

![Native War room workspace](assets/warroom-native-workspace.png)
