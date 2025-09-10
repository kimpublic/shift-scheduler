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
	expiry := time.Now().Add(1 * time.Hour)

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
		return Session{}, false
	}

	sMu.Lock()
	s, ok := sessions[c.Value]
	// 만료 체크: 만료면 세션 제거 + 쿠키 무효화
	if ok && !s.Expires.IsZero() && time.Now().After(s.Expires) {
		delete(sessions, c.Value)
		sMu.Unlock()

		// 쿠키 즉시 무효화
		http.SetCookie(w, &http.Cookie{
			Name:     "sid",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
		return Session{}, false
	}
	sMu.Unlock()

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

// 역할에 따른 리다이렉트
func redirectByRole(w http.ResponseWriter, r *http.Request, role string) {
	switch role {
	case "admin":
		http.Redirect(w, r, "/approval", http.StatusFound)
	default:
		http.Redirect(w, r, "/schedule", http.StatusFound)
	}
}

// 메인 페이지 핸들러
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if s, ok := currentUser(w, r); ok {
		redirectByRole(w, r, s.Role)
		return
	}
	_ = tmpl.ExecuteTemplate(w, "base.html", map[string]any{
		"Error": "",
	})
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
	redirectByRole(w, r, role)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func scheduleHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "student" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Schedule placeholder for user1"))
}

// GET "/approval": 관리자 전용(플레이스홀더)
func approvalHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := currentUser(w, r)
	if !ok || s.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Approval placeholder for admin"))
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
