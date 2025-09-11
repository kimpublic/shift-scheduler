package main

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	Username string
	Role     string
	Expires  time.Time
}

var (
	tmpl     = template.Must(template.ParseGlob("templates/*.html"))
	sessions = map[string]Session{}
	sMu      sync.Mutex
)

// 새 세션 ID 생성
func newSessionID() string {
	var b [16]byte
	_, _ = cryptoRand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// 생성된 세션 저장 및 쿠키 생성
func setSession(w http.ResponseWriter, sess Session) {
	sid := newSessionID()
	// 세션/쿠키 만료시간을 '동일'하게 정의
	expiry := time.Now().Add(3 * time.Minute)

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
		// 프로덕션이면 true 권장 (HTTPS 전제)
		// Secure: true,
		Expires: expiry, // 쿠키도 동일 만료
		// MaxAge: int(time.Until(expiry).Seconds()), // 원하면 MaxAge도 같이
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

// 헬퍼: HTMX 요청 여부
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
		// Expires: time.Now().Add(12*time.Hour), // 필요 시 사용
	})

	// 역할별 리다이렉트
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
	render(w, "schedule.html", map[string]any{
		"User": s.Username, "Role": s.Role, "Error": "",
	})
}

// GET "/approval": 관리자 전용(플레이스홀더)
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
	render(w, "approval.html", map[string]any{
		"User": s.Username, "Role": s.Role, "Error": "",
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
	// page: "login.html", "schedule.html" 등
	t := template.Must(template.ParseFiles(
		"templates/base.html",
		"templates/"+page,
	))
	// base.html 안의 {{block "content"}}에 page의 {{define "content"}}가 매핑됨
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

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}

}
