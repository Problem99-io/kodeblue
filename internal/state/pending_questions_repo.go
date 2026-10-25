package state

import (
	"database/sql"
	"encoding/json"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

const (
	PendingQuestionStatusPending  = "pending"
	PendingQuestionStatusAnswered = "answered"
	PendingQuestionStatusIgnored  = "ignored"
)

type PendingQuestionRepo struct {
	db *DB
}

func NewPendingQuestionRepo(db *DB) *PendingQuestionRepo {
	return &PendingQuestionRepo{db: db}
}

func (r *PendingQuestionRepo) Create(q internal.PendingQuestion) error {
	options, err := json.Marshal(q.Options)
	if err != nil {
		return err
	}
	recommendedChoices, err := json.Marshal(q.RecommendedChoices)
	if err != nil {
		return err
	}
	custom := 0
	if q.Custom {
		custom = 1
	}
	kind := q.Kind
	if kind == "" {
		kind = internal.QuestionKindAskUser
	}
	createdAt := q.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	_, err = r.db.Exec(
		`INSERT INTO pending_questions (id, session_id, run_id, kind, title, question, mode, options, custom, recommended, recommended_choices, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
		 ON CONFLICT(id) DO UPDATE SET
		   session_id = excluded.session_id,
		   run_id = excluded.run_id,
		   kind = excluded.kind,
		   title = excluded.title,
		   question = excluded.question,
		   mode = excluded.mode,
		   options = excluded.options,
		   custom = excluded.custom,
		   recommended = excluded.recommended,
		   recommended_choices = excluded.recommended_choices`,
		q.QuestionID, string(q.SessionID), string(q.RunID), kind, q.Title, q.Question, q.Mode,
		string(options), custom, q.Recommended, string(recommendedChoices), createdAt.Unix(),
	)
	return err
}

func (r *PendingQuestionRepo) Get(id string) (*internal.PendingQuestion, string, error) {
	row := r.db.conn.QueryRow(
		`SELECT id, session_id, run_id, kind, title, question, mode, options, custom, recommended, recommended_choices, status, created_at
		 FROM pending_questions WHERE id = ?`, id,
	)
	question, status, err := scanPendingQuestion(row)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return &question, status, nil
}

func (r *PendingQuestionRepo) ListPendingBySession(sessionID internal.SessionID, cutoff time.Time) ([]internal.PendingQuestion, error) {
	// Stop cancels the owning run, but older runtimes could leave its durable
	// questions pending. They must not keep a later completed run awaiting_user.
	// Interrupted runs remain recoverable.
	rows, err := r.db.conn.Query(
		`SELECT id, session_id, run_id, kind, title, question, mode, options, custom, recommended, recommended_choices, status, created_at
		 FROM pending_questions
		 WHERE session_id = ? AND status IN ('pending', 'resuming') AND created_at >= ?
		 AND NOT EXISTS (
		   SELECT 1 FROM runs
		   WHERE runs.id = pending_questions.run_id
		     AND runs.session_id = pending_questions.session_id
		     AND runs.status = 'aborted'
		 )
		 ORDER BY created_at ASC`,
		string(sessionID), cutoff.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var questions []internal.PendingQuestion
	for rows.Next() {
		question, _, err := scanPendingQuestion(rows)
		if err != nil {
			return nil, err
		}
		questions = append(questions, question)
	}
	return questions, rows.Err()
}

// ListPendingByRun returns the questions for a single run that are still awaiting
// an answer (within the retention cutoff). Used to decide when every question in
// an interrupted run's batch has been answered.
func (r *PendingQuestionRepo) ListPendingByRun(runID internal.RunID, cutoff time.Time) ([]internal.PendingQuestion, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, session_id, run_id, kind, title, question, mode, options, custom, recommended, recommended_choices, status, created_at
		 FROM pending_questions
		 WHERE run_id = ? AND status = 'pending' AND created_at >= ?
		 ORDER BY created_at ASC`,
		string(runID), cutoff.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var questions []internal.PendingQuestion
	for rows.Next() {
		question, _, err := scanPendingQuestion(rows)
		if err != nil {
			return nil, err
		}
		questions = append(questions, question)
	}
	return questions, rows.Err()
}

// AnsweredQuestion pairs a resolved question with the answer the user gave.
type AnsweredQuestion struct {
	Question internal.PendingQuestion
	Answer   internal.QuestionAnswer
}

// ListAnsweredByRun returns the answered questions for a run (within the retention
// cutoff), in ask order, along with the recorded answers. Used to reconstruct the
// user's reply when resuming an interrupted run.
func (r *PendingQuestionRepo) ListAnsweredByRun(runID internal.RunID, cutoff time.Time) ([]AnsweredQuestion, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, session_id, run_id, kind, title, question, mode, options, custom, recommended, recommended_choices, status, created_at, answer
		 FROM pending_questions
		 WHERE run_id = ? AND status IN ('answered', 'resuming') AND created_at >= ?
		 ORDER BY created_at ASC`,
		string(runID), cutoff.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var answered []AnsweredQuestion
	for rows.Next() {
		var answerJSON sql.NullString
		question, _, err := scanPendingQuestionWithAnswer(rows, &answerJSON)
		if err != nil {
			return nil, err
		}
		var answer internal.QuestionAnswer
		if answerJSON.Valid && answerJSON.String != "" {
			if err := json.Unmarshal([]byte(answerJSON.String), &answer); err != nil {
				answer = internal.QuestionAnswer{}
			}
		}
		answered = append(answered, AnsweredQuestion{Question: question, Answer: answer})
	}
	return answered, rows.Err()
}

func (r *PendingQuestionRepo) Resolve(id string, status string, answer internal.QuestionAnswer) error {
	answerJSON, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	resolvedAt := answer.AnsweredAt
	if resolvedAt.IsZero() {
		resolvedAt = time.Now()
	}
	_, err = r.db.Exec(
		`UPDATE pending_questions SET status = ?, answer = ?, resolved_at = ? WHERE id = ? AND status IN ('pending', 'resuming')`,
		status, string(answerJSON), resolvedAt.Unix(), id,
	)
	return err
}

type pendingQuestionScanner interface {
	Scan(dest ...any) error
}

func scanPendingQuestion(scanner pendingQuestionScanner) (internal.PendingQuestion, string, error) {
	var q internal.PendingQuestion
	var optionsJSON string
	var recommendedChoicesJSON string
	var custom int
	var status string
	var createdAt int64
	err := scanner.Scan(
		&q.QuestionID,
		&q.SessionID,
		&q.RunID,
		&q.Kind,
		&q.Title,
		&q.Question,
		&q.Mode,
		&optionsJSON,
		&custom,
		&q.Recommended,
		&recommendedChoicesJSON,
		&status,
		&createdAt,
	)
	if err != nil {
		return internal.PendingQuestion{}, "", err
	}
	return hydratePendingQuestion(q, optionsJSON, recommendedChoicesJSON, custom, createdAt), status, nil
}

// scanPendingQuestionWithAnswer scans the standard columns plus the answer JSON
// (captured into the caller-provided NullString) for resolved-question queries.
func scanPendingQuestionWithAnswer(scanner pendingQuestionScanner, answerJSON *sql.NullString) (internal.PendingQuestion, string, error) {
	var q internal.PendingQuestion
	var optionsJSON string
	var recommendedChoicesJSON string
	var custom int
	var status string
	var createdAt int64
	err := scanner.Scan(
		&q.QuestionID,
		&q.SessionID,
		&q.RunID,
		&q.Kind,
		&q.Title,
		&q.Question,
		&q.Mode,
		&optionsJSON,
		&custom,
		&q.Recommended,
		&recommendedChoicesJSON,
		&status,
		&createdAt,
		answerJSON,
	)
	if err != nil {
		return internal.PendingQuestion{}, "", err
	}
	return hydratePendingQuestion(q, optionsJSON, recommendedChoicesJSON, custom, createdAt), status, nil
}

func hydratePendingQuestion(q internal.PendingQuestion, optionsJSON, recommendedChoicesJSON string, custom int, createdAt int64) internal.PendingQuestion {
	q.Custom = custom != 0
	q.CreatedAt = time.Unix(createdAt, 0)
	if err := json.Unmarshal([]byte(optionsJSON), &q.Options); err != nil {
		q.Options = []string{}
	}
	if err := json.Unmarshal([]byte(recommendedChoicesJSON), &q.RecommendedChoices); err != nil {
		q.RecommendedChoices = []string{}
	}
	return q
}

// ReopenAfterResumeFailure leaves the checkpoint actionable after dispatch fails.
func (r *PendingQuestionRepo) ReopenAfterResumeFailure(id string) error {
	_, err := r.db.Exec(`UPDATE pending_questions SET status = 'pending', answer = '', resolved_at = NULL WHERE id = ? AND status IN ('answered', 'resuming')`, id)
	return err
}
