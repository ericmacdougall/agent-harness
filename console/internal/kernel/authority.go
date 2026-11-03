package kernel

// factWrites is the field-to-fact table: which Session fields each session fact may
// change. A test walks random histories and fails on any write not listed here, and
// on any authority field with no writing fact. Revision changes with every fact.
var factWrites = map[FactKind][]string{
	FactSessionCreated:            {"ID", "Provider", "ProviderID", "ProfileID", "CWD", "Requests", "Connected"},
	FactConversationBound:         {"ProviderID", "ConversationStarted"},
	FactProviderConnected:         {"Connected"},
	FactProviderDisconnected:      {"Connected", "Requests", "Inputs", "ProviderFinal", "Questions", "Children", "TurnID"},
	FactRuntimeIdentityBound:      {"RuntimeIdentity"},
	FactAuthBoundaryCrossed:       {"Requests", "Inputs", "ProviderFinal", "ReadOnly", "Connected", "ControlEpoch", "Questions", "Children", "TurnID", "Supervision", "PendingInterrupt", "Review", "Task"},
	FactCwdChanged:                {"CWD", "ControlEpoch"},
	FactSessionClosed:             {"Closed"},
	FactAbandoned:                 {"Requests", "ProviderFinal", "Task", "Abandoned", "PendingInterrupt", "ReadOnly", "Connected", "ControlEpoch", "Questions", "Children", "Inputs", "Supervision", "Review", "ReviewResultPending"},
	FactSessionQuarantined:        {"Quarantine", "ReadOnly", "Connected", "Review", "Task"},
	FactSupervisionChanged:        {"Supervision"},
	FactCascadeSelected:           {"Cascade"},
	FactPolicyBound:               {"PolicyRevision"},
	FactContinuationBudgetChanged: {"Supervision"},
	FactRequestIntended:           {"Requests", "LastRequest", "RequestOrder", "TurnID", "FinalStatus", "ProviderFinal", "PendingInterrupt", "PauseUnconfirmed", "LastRefusal", "Questions", "Task", "Supervision"},
	FactProviderAccepted:          {"Requests"},
	FactProviderRefused:           {"Requests", "Inputs", "Questions", "TurnID", "PendingInterrupt", "Task", "LastRefusal", "Supervision"},
	FactProviderCompleted:         {"Requests", "ProviderFinal", "FinalStatus", "PauseUnconfirmed", "PendingInterrupt", "TurnID", "Questions", "Inputs"},
	FactOutcomeUnknown:            {"Requests", "ProviderFinal", "Questions", "Inputs", "Supervision"},
	FactTurnBound:                 {"TurnID", "PendingInterrupt"},
	FactLateFrameObserved:         {"Evidence"},
	FactAdmissionRefused:          {"LastRefusal"},
	FactControlRequested:          {"Supervision", "Inputs", "ControlEpoch", "Questions", "Task", "PendingInterrupt"},
	FactControlOutcome:            {"PauseUnconfirmed"},
	FactQuestionOpened:            {"Questions"},
	FactQuestionAnswered:          {"Questions"},
	FactQuestionRevoked:           {"Questions"},
	FactChildObserved:             {"Children"},
	FactChildControlOutcome:       {"Children"},
	FactChildQuarantined:          {"Children"},
	FactInputQueued:               {"Inputs"},
	FactInputDispatchPrepared:     {"Task", "Inputs"},
	FactInputOutcome:              {"Inputs"},
	FactInputDiscarded:            {"Inputs"},
	FactPayloadReleased:           {"Inputs"},
	FactReviewStarted:             {"Review", "Task"},
	FactReviewCancelled:           {"Review", "ReviewResultPending", "Task"},
	FactReviewOutcome:             {"Review", "Task"},
	FactReviewResultPending:       {"ReviewResultPending"},
	FactCheckpointRecorded:        {"Task"},
	FactLegacyInputHeld:           {"Inputs"},
}

// restartWrites is the same list for the one global fact that touches sessions.
var restartWrites = []string{"Requests", "ProviderFinal", "ReadOnly", "Connected", "TurnID", "PendingInterrupt", "PauseUnconfirmed", "Questions", "Inputs", "Review", "Task", "ReviewResultPending", "Children", "Supervision", "Hidden"}
