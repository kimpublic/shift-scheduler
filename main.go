package main

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===== 스케줄 도메인 =====
type Interval struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Minutes int    `json:"minutes"`
}

type Day struct {
	Day          string     `json:"day"`
	Intervals    []Interval `json:"intervals"`
	TotalMinutes int        `json:"totalMinutes"`
}

type SchedulePayload struct {
	Days               []Day `json:"days"`
	WeeklyTotalMinutes int   `json:"weeklyTotalMinutes"`
}

type ScheduleStatus string

const (
	StatusDraft    ScheduleStatus = "Draft"
	StatusPending  ScheduleStatus = "Pending"
	StatusApproved ScheduleStatus = "Approved"
	StatusRejected ScheduleStatus = "Rejected"
	StatusExpired  ScheduleStatus = "Expired"
)

type ScheduleRecord struct {
	ID          string
	Version     int
	User        string
	Payload     SchedulePayload
	Status      ScheduleStatus
	Comment     string
	SubmittedAt time.Time
	ReviewedAt  *time.Time
}

var (
	submissionsByID   = map[string]*ScheduleRecord{}
	userSubmissionIDs = map[string][]string{}
	userLatestID      = map[string]string{}
	scMu              sync.Mutex
)

const (
	MinShiftMin  = 3 * 60
	MaxDailyMin  = 9 * 60
	MinWeeklyMin = 20 * 60
	MaxWeeklyMin = 40 * 60
	DayStartMin  = 8 * 60
	DayEndMin    = 18 * 60
)

type Session struct {
	Username string
	Role     string
	Expires  time.Time
}

var (
	funcMap = template.FuncMap{
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"mod": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a % b
		},
	}

	tmpl     = template.Must(template.New("all").Funcs(funcMap).ParseGlob("templates/*.html"))
	sessions = map[string]Session{}
	sMu      sync.Mutex
)

func parseHHMM(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time: %s", s)
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid time: %s", s)
	}
	return h*60 + m, nil
}

func validateServer(p SchedulePayload) (ok bool, messages []string, fixed SchedulePayload) {
	weekly := 0
	hasShort := false
	hasOverDaily := false

	// 서버에서 일일합/주합 재계산 & 범위 확인
	for i, d := range p.Days {
		dayTotal := 0
		for _, seg := range d.Intervals {
			s, err1 := parseHHMM(seg.Start)
			e, err2 := parseHHMM(seg.End)
			if err1 != nil || err2 != nil || e <= s {
				return false, []string{"시간 형식이 올바르지 않습니다."}, p
			}
			if s < DayStartMin || e > DayEndMin {
				return false, []string{"선택 시간은 08:00~18:00 범위여야 합니다."}, p
			}
			mins := e - s
			dayTotal += mins
			if mins < MinShiftMin {
				hasShort = true
			}
		}
		p.Days[i].TotalMinutes = dayTotal
		weekly += dayTotal
		if dayTotal > MaxDailyMin {
			hasOverDaily = true
		}
	}
	p.WeeklyTotalMinutes = weekly

	if hasShort {
		messages = append(messages, "A shift should be more than 3 hours.")
	}
	if hasOverDaily {
		messages = append(messages, "'A day's total working hours must not exceed 9 hours.")
	}
	if weekly < MinWeeklyMin || weekly > MaxWeeklyMin {
		messages = append(messages,
			fmt.Sprintf("Weekly Total: %dh %dm (Required Hours: %dh %dm–%dh %dm)",
				weekly/60, weekly%60, MinWeeklyMin/60, MinWeeklyMin%60, MaxWeeklyMin/60, MaxWeeklyMin%60))
	}
	return len(messages) == 0, messages, p
}

func newSubmissionID() string { return newSessionID() }

// POST "/schedule/submit" 유저 제출
func scheduleSubmitHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "student" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw := r.FormValue("schedule_json")
	var payload SchedulePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ok2, msgs, fixed := validateServer(payload)
	if !ok2 {
		w.WriteHeader(422)
		_, _ = fmt.Fprintf(w, `
		<div class="status-banner" id="status-banner" data-status="Draft">Status: Draft</div>
		<div id="validation-banner" class="status-banner validation show" hx-swap-oob="true">Validation: %s</div>`,
			template.HTMLEscapeString(strings.Join(msgs, " | ")))
		return

	}

	// 기존 Pending들을 Expired 처리 + 새 제출을 Pending으로 저장
	scMu.Lock()
	defer scMu.Unlock()

	// 해당 유저의 기존 Pending 모두 Expired
	if ids := userSubmissionIDs[s.Username]; len(ids) > 0 {
		expireTS := time.Now()
		for _, oldID := range ids {
			if old := submissionsByID[oldID]; old != nil && old.Status == StatusPending {
				old.Status = StatusExpired
				old.ReviewedAt = &expireTS
			}
		}
	}

	// 새 제출 생성 (항상 새로운 버전으로 append)
	id := newSubmissionID()
	now := time.Now()
	ver := len(userSubmissionIDs[s.Username]) + 1
	rec := &ScheduleRecord{
		ID:          id,
		Version:     ver,
		User:        s.Username,
		Payload:     fixed,
		Status:      StatusPending,
		Comment:     "",
		SubmittedAt: now,
		ReviewedAt:  nil,
	}
	submissionsByID[id] = rec
	userSubmissionIDs[s.Username] = append(userSubmissionIDs[s.Username], id)
	userLatestID[s.Username] = id

	// 성공 응답
	_, _ = fmt.Fprintf(w, `
	<div class="status-banner" id="status-banner" data-status="Pending">Status: Pending Approval</div>
	<div id="validation-banner" class="status-banner validation" hx-swap-oob="true"></div>`)

}

// POST "/admin/approve"
func adminApproveHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	scMu.Lock()
	rec, exists := submissionsByID[id]
	if !exists {
		scMu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if rec.Status != StatusPending {
		scMu.Unlock()
		w.WriteHeader(409)
		_ = tmpl.ExecuteTemplate(w, "approval_row", rec)
		return
	}

	now := time.Now()
	rec.Status = StatusApproved
	rec.ReviewedAt = &now
	scMu.Unlock()

	// 행 교체 → 상태 뱃지/버튼 비활성 자동 반영
	_ = tmpl.ExecuteTemplate(w, "approval_row", rec)
}

// POST "/admin/reject"
func adminRejectHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	id := r.FormValue("id")
	comment := strings.TrimSpace(r.FormValue("comment"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	scMu.Lock()
	rec, exists := submissionsByID[id]
	if !exists {
		scMu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if rec.Status != StatusPending {
		scMu.Unlock()
		w.WriteHeader(409)
		_ = tmpl.ExecuteTemplate(w, "approval_row", rec)
		return
	}

	if comment == "" {
		scMu.Unlock()
		w.WriteHeader(422)
		_ = tmpl.ExecuteTemplate(w, "approval_row", rec)
		return
	}

	now := time.Now()
	rec.Status = StatusRejected
	rec.Comment = comment
	rec.ReviewedAt = &now
	scMu.Unlock()

	_ = tmpl.ExecuteTemplate(w, "approval_row", rec)
}

// 새 세션 ID 생성
func newSessionID() string {
	var b [16]byte
	_, _ = cryptoRand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// 생성된 세션 저장 및 쿠키 생성
func setSession(w http.ResponseWriter, sess Session) {
	sid := newSessionID()
	// 세션/쿠키 만료시간 정의
	expiry := time.Now().Add(15 * time.Minute)

	sess.Expires = expiry

	sMu.Lock()
	sessions[sid] = sess
	sMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiry,
	})
}

// 현재 사용자 조회
func currentUser(w http.ResponseWriter, r *http.Request) (Session, bool) {
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		sMu.Lock()
		size := len(sessions)
		sMu.Unlock()
		log.Printf("[currentUser] no cookie (err=%v). sessions=%d", err, size)
		return Session{}, false
	}

	sMu.Lock()
	s, ok := sessions[c.Value]
	// 만료 체크: 만료면 세션 제거 + 쿠키 무효화
	expired := ok && !s.Expires.IsZero() && time.Now().After(s.Expires)
	if expired {
		delete(sessions, c.Value)
		sMu.Unlock()
		// 쿠키 즉시 무효화
		http.SetCookie(w, &http.Cookie{
			Name: "sid", Value: "", Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
			MaxAge: -1, Expires: time.Unix(0, 0),
		})
		log.Printf("[currentUser] expired cookie sid=%q -> cleared", c.Value)
		return Session{}, false
	}
	sMu.Unlock()
	log.Printf("cookie sid=%q, found=%v, expired=%v", c.Value, ok, ok && time.Now().After(s.Expires))

	return s, ok
}

// 세션 삭제 및 쿠키 만료
func clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil && c.Value != "" {
		sMu.Lock()
		delete(sessions, c.Value)
		sMu.Unlock()
	}
	// 쿠키 완전 무효화 (Expires + MaxAge 둘 다)
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// HTMX 요청 여부
func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

func redirectByRoleHTMX(w http.ResponseWriter, r *http.Request, role string) {
	target := "/schedule"
	if role == "admin" {
		target = "/approval"
	}
	if isHTMX(r) {
		// 전체 리로드 대신 클라이언트가 location 변경
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// 메인 페이지 핸들러
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if s, ok := currentUser(w, r); ok {
		redirectByRoleHTMX(w, r, s.Role)
		return
	}
	render(w, "login.html", map[string]any{"Error": ""})
}

// 로그인 핸들러
func loginHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = tmpl.ExecuteTemplate(w, "base.html", map[string]any{
			"Error": "Username and password are required.",
		})
		return
	}
	if password != "password" {
		w.WriteHeader(http.StatusUnauthorized)
		_ = tmpl.ExecuteTemplate(w, "base.html", map[string]any{
			"Error": "Invalid username or password.",
		})
		return
	}

	// 사용자/역할 결정: admin 이랑 user1만 허용
	var role string
	switch username {
	case "admin":
		role = "admin"
	case "user1":
		role = "student"
	default:
		w.WriteHeader(http.StatusUnauthorized)
		_ = tmpl.ExecuteTemplate(w, "base.html", map[string]any{
			"Error": "Invalid username or password.",
		})
		return
	}

	// 세션 저장 + 쿠키 발급
	setSession(w, Session{
		Username: username,
		Role:     role,
	})

	redirectByRoleHTMX(w, r, role)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func scheduleHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "student" {
		if isHTMX(r) {
			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	status := "Draft"
	var savedJSON template.JS = "null"
	rejectComment := ""

	scMu.Lock()
	if latestID, ok := userLatestID[s.Username]; ok {
		if rec := submissionsByID[latestID]; rec != nil {
			status = string(rec.Status)
			if b, err := json.Marshal(rec.Payload); err == nil {
				savedJSON = template.JS(b)
			}
			if rec.Status == StatusRejected {
				rejectComment = rec.Comment
			}
		}
	}
	scMu.Unlock()

	render(w, "schedule.html", map[string]any{
		"User":          s.Username,
		"Role":          s.Role,
		"Status":        status,
		"SavedJSON":     savedJSON,
		"RejectComment": rejectComment,
		"Error":         "",
	})
}

// GET "/approval": 관리자 전용
func approvalHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "admin" {
		if isHTMX(r) {
			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// 최근 제출 순으로 정렬
	list := []*ScheduleRecord{}
	scMu.Lock()
	for _, rec := range submissionsByID {
		list = append(list, rec)
	}
	scMu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		return list[i].SubmittedAt.After(list[j].SubmittedAt)
	})

	render(w, "approval.html", map[string]any{
		"User": s.Username, "Role": s.Role, "Error": "", "Items": list,
	})
}

func startSessionGC() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			now := time.Now()
			sMu.Lock()
			for sid, s := range sessions {
				if !s.Expires.IsZero() && now.After(s.Expires) {
					delete(sessions, sid)
				}
			}
			sMu.Unlock()
		}
	}()
}

func render(w http.ResponseWriter, page string, data any) {
	t := template.Must(
		template.New("base").
			Funcs(funcMap).
			ParseFiles(
				"templates/base.html",
				"templates/"+page,
			),
	)
	_ = t.ExecuteTemplate(w, "base.html", data)
}

func main() {

	startSessionGC()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			indexHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			loginHandler(w, r)
			return
		}
		// GET /login 요청은 루트로 통일
		http.Redirect(w, r, "/", http.StatusFound)
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			logoutHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	http.HandleFunc("/schedule", scheduleHandler)
	http.HandleFunc("/approval", approvalHandler)

	http.HandleFunc("/schedule/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			scheduleSubmitHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	http.HandleFunc("/admin/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminApproveHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	http.HandleFunc("/admin/reject", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminRejectHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}

}
